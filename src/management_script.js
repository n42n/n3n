var verbose=-1;

function rows2verbose(id, unused, data) {
    row0 = data[0]
    verbose = row0['traceLevel']

    let div = document.getElementById(id);
    div.innerHTML=verbose
}

function rows2keyvalue(id, keys, data) {
    let s = "<table border=1 cellspacing=0>"
    data.forEach((row) => {
        keys.forEach((key) => {
            if (key in row) {
                s += "<tr><th>" + key + "<td>" + row[key];
            }
        });
    });

    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function rows2keyvalueall(id, unused, data) {
    let s = "<table border=1 cellspacing=0>"
    data.forEach((row) => {
        Object.keys(row).forEach((key) => {
            s += "<tr><th>" + key + "<td>" + row[key];
        });
    });

    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function rows2table(id, columns, data) {
    let s = "<table border=1 cellspacing=0>"
    s += "<tr>"
    columns.forEach((col) => {
        s += "<th>" + col
    });
    data.forEach((row) => {
        s += "<tr>"
        columns.forEach((col) => {
            val = row[col]
            if (typeof val === "undefined") {
                val = ''
            }
            s += "<td>" + val
        });
    });

    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function do_get(url, id, handler, handler_param) {
    fetch(url)
      .then(function (response) {
        if (!response.ok) {
            throw new Error('Fetch got ' + response.status)
        }
        return response.json();
      })
      .then(function (data) {
        handler(id,handler_param,data);

        // update the timestamp on success
        let now = Math.round(new Date().getTime() / 1000);
        let time = document.getElementById('time');
        time.innerHTML=now;
      })
      .catch(function (err) {
        console.log('error: ' + err);
      });
}

function do_post(url, body, id, handler, handler_param) {
    fetch(url, {method:'POST', body: body})
      .then(function (response) {
        if (!response.ok) {
            throw new Error('Fetch got ' + response.status)
        }
        return response.json();
      })
      .then(function (data) {
        handler(id,handler_param,data);
      })
      .catch(function (err) {
        console.log('error: ' + err);
      });
}

function do_stop(tracelevel) {
    // FIXME: uses global in script library
    fetch(nodetype + '/stop', {method:'POST'})
}

function setverbose(tracelevel) {
    if (tracelevel < 0) {
        tracelevel = 0;
    }
    // FIXME: uses global in script library
    do_post(
        nodetype + '/verbose', tracelevel, 'verbose',
        rows2verbose, null
    );
}

function refresh_setup(interval) {
    var timer = setInterval(refresh_job, interval);
}
