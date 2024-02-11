/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <n3n/logging.h> // for traceEvent
#include <n3n/random.h>
#include <errno.h>   // for errno, EAGAIN
#include <stddef.h>  // for NULL, size_t
#include <time.h>    // for clock, time
#include <unistd.h>  // for syscall

// syscall and inquiring random number from hardware generators might fail, so
// we will retry
#define RND_RETRIES      1000


#if defined (__linux__)
#include <syscall.h>  // for SYS_getrandom
#ifdef SYS_getrandom
#define GRND_NONBLOCK       1
#endif
#endif

#if defined (__RDRND__) || defined (__RDSEED__)
#include <immintrin.h>  /* _rdrand64_step, rdseed4_step */
// may need x86intrin.h with gcc
// see https://gcc.gnu.org/legacy-ml/gcc-bugs/2015-11/msg01051.html
#endif

#ifdef _WIN32
#include "win32/defs.h"
#include <wincrypt.h>   // HCTYPTPROV, Crypt*-functions
#endif

typedef struct rn_generator_state_t {
    uint64_t a, b;
} rn_generator_state_t;

typedef struct splitmix64_state_t {
    uint64_t s;
} splitmix64_state_t;




// the following code offers an alterate pseudo random number generator
// namely XORSHIFT128+ to use instead of C's rand()
// its performance is on par with C's rand()


// the state must be seeded in a way that it is not all zero, choose some
// arbitrary defaults (in this case: taken from splitmix64)
static rn_generator_state_t rn_current_state = {
    .a = 0x9E3779B97F4A7C15,
    .b = 0xBF58476D1CE4E5B9
};


// used for mixing the initializing seed
static uint64_t splitmix64 (splitmix64_state_t *state) {

    uint64_t result = state->s;

    state->s = result + 0x9E3779B97F4A7C15;

    result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
    result = (result ^ (result >> 27)) * 0x94D049BB133111EB;

    return result ^ (result >> 31);
}


static int n3n_srand (uint64_t seed) {

    uint8_t i;
    splitmix64_state_t smstate = { seed };

    rn_current_state.a = 0;
    rn_current_state.b = 0;

    rn_current_state.a = splitmix64(&smstate);
    rn_current_state.b = splitmix64(&smstate);

    // the following lines could be deleted as soon as it is formally prooved that
    // there is no seed leading to (a == b == 0). until then, just to be safe:
    if((rn_current_state.a == 0) && (rn_current_state.b == 0)) {
        rn_current_state.a = 0x9E3779B97F4A7C15;
        rn_current_state.b = 0xBF58476D1CE4E5B9;
    }

    // stabilize in unlikely case of weak state with only a few bits set
    for(i = 0; i < 32; i++)
        n3n_rand();

    return 0;
}


// the following code of xorshift128p was taken from
// https://en.wikipedia.org/wiki/Xorshift as of July, 2019
// and thus is considered public domain
uint64_t n3n_rand (void) {

    uint64_t t       = rn_current_state.a;
    uint64_t const s = rn_current_state.b;

    rn_current_state.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    rn_current_state.b = t;

    return t + s;
}

#ifdef SYS_getrandom
static uint64_t seed_getrandom() {
    int retries = RND_RETRIES;
    int rc;
    uint64_t seed;

    while(retries--) {
        rc = syscall(SYS_getrandom, &seed, sizeof(seed), GRND_NONBLOCK);
        if(rc == sizeof(seed)) {
            return seed;
        }
        if(rc != -1) {
            // Dunno, still warming up?
            continue;
        }
        if(errno != EAGAIN) {
            traceEvent(TRACE_ERROR, "getrandom() error errno=%u", errno);
            return 0;
        }
    }

    // if we get here, we must have run out of retries
    if(errno == EAGAIN) {
        traceEvent(
            TRACE_ERROR,
            "getrandom syscall indicate not being able to provide enough entropy yet."
            );
    }
    return 0;
}
#endif

#ifdef __RDRND__
// __RDRND__ is set only if architecturual feature is set, e.g. compiled with -march=native
static uint64_t seed_rdrnd() {
    uint64_t seed;
    size_t j = 0;
    for(j = 0; j < RND_RETRIES; j++) {
        if(_rdrand64_step((unsigned long long*)&seed)) {
            // success!
            return seed;
        }
        // continue loop to try again otherwise
    }

    traceEvent(
        TRACE_ERROR,
        "unable to get a hardware generated random number from RDRND."
        );
    return 0;
}
#endif

#ifdef __RDSEED__
#if __GNUC__ > 4
// __RDSEED__ is set only if architecturual feature is set, e.g. compile with -march=native
static uint64_t seed_rdseed() {
    uint64_t seed;
    size_t k = 0;
    for(k = 0; k < RND_RETRIES; k++) {
        if(_rdseed64_step((unsigned long long*)&seed)) {
            // success!
            return seed;
        }
        // continue loop to try again otherwise
    }

    traceEvent(
        TRACE_ERROR,
        "unable to get a hardware generated random number from RDSEED."
        );
    return 0;
}
#endif
#endif

#ifdef _WIN32
static uint64_t seed_CryptGenRandom() {
    uint64_t seed;
    HCRYPTPROV crypto_provider;
    CryptAcquireContext(&crypto_provider, NULL, NULL,
                        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(crypto_provider, 8, &seed);
    CryptReleaseContext(crypto_provider, 0);
    return seed;
}
#endif

static uint64_t seed_time() {
    return time(NULL);
}

static uint64_t seed_clock() {
    uint64_t seed = clock();    /* ticks since program start */
    seed *= 18444244737;
    return seed;
}

const struct n3n_rand_seeds_def n3n_rand_seeds[] = {
#ifdef SYS_getrandom
    {
        .name = "SYS_getrandom",
        .seed = &seed_getrandom,
    },
#endif
#ifdef __RDRND__
    {
        .name = "RDRND",
        .seed = &seed_rdrnd,
    },
#endif
#ifdef __RDSEED__
#if __GNUC__ > 4
    {
        .name = "RDSEED",
        .seed = &seed_rdseed,
    },
#endif
#endif
#ifdef _WIN32
    {
        .name = "CryptGenRandom",
        .seed = &seed_CryptGenRandom,
    },
#endif
    {
        .name = "time",
        .seed = &seed_time
    },
    {
        .name = "clock",
        .seed = &seed_clock
    },
};

// the following code tries to gather some entropy from several sources
// for use as seed. Note, that this code does not set the random generator
// state yet, a call to   n3n_srand (n3n_seed())   would do
static uint64_t n3n_seed (void) {

    uint64_t ret = 0;    /* this could even go uninitialized */

    int i;
    for(i = 0; i < sizeof(n3n_rand_seeds) / sizeof(n3n_rand_seeds[0]); i++) {
        // A zero return, means there was an issue (TODO: report that?)
        // as we want randomness, it does no harm to add up even uninitialized
        // values or erroneously arbitrary values returned from the syscall
        // for the first time
        ret += n3n_rand_seeds[i].seed();
    }

    return ret;
}

// an integer squrare root approximation
// from https://stackoverflow.com/a/1100591
static int ftbl[33] = {
    0, 1, 1, 2, 2, 4, 5, 8, 11, 16, 22, 32, 45, 64, 90,
    128, 181,256,362, 512, 724, 1024, 1448, 2048, 2896,
    4096, 5792, 8192, 11585, 16384, 23170, 32768, 46340
};


static int ftbl2[32] = {
    32768, 33276, 33776, 34269, 34755, 35235, 35708, 36174,
    36635, 37090, 37540, 37984, 38423, 38858, 39287, 39712,
    40132, 40548, 40960, 41367, 41771, 42170, 42566, 42959,
    43347, 43733, 44115, 44493, 44869, 45241, 45611, 45977
};


static int i_sqrt (int val) {

    int cnt = 0;
    int t = val;

    while(t) {
        cnt++;
        t>>=1;
    }

    if(6 >= cnt)
        t = (val << (6-cnt));
    else
        t = (val >> (cnt-6));

    return (ftbl[cnt] * ftbl2[t & 31]) >> 15;
}


static int32_t int_sqrt (int val) {

    int ret;

    ret  = i_sqrt(val);
    ret += i_sqrt(val - ret * ret) / 16;

    return ret;
}


// returns a random number from [0, max_n] with higher probability towards the borders
uint32_t n3n_rand_sqr (uint32_t max_n) {

    uint32_t raw_max = 0;
    uint32_t raw_rnd = 0;
    int32_t ret     = 0;

    raw_max = (max_n+2) * (max_n+2);
    raw_rnd = n3n_rand() % (raw_max);

    ret = int_sqrt(raw_rnd) / 2;
    ret = (raw_rnd & 1) ? ret : -ret;
    ret = max_n / 2 + ret;

    if(ret < 0)
        ret = 0;
    if(ret > max_n)
        ret = max_n;

    return ret;
}

void n3n_initfuncs_random () {
    /* Random seed */
    n3n_srand(n3n_seed());
}
