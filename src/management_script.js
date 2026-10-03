var verbose=-1;
var jsonrpc_id=1;   // incremented on each request

// Text as HTML: names and descriptions come from other peers, and must not
// become markup in this page
function esc(val) {
    return String(val)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function result2verbose(id, unused, data) {
    verbose = data;
    let div = document.getElementById(id);
    div.textContent=verbose;
}

function rows2keyvalue(id, keys, data) {
    let s = "<table border=1 cellspacing=0>"
    data.forEach((row) => {
        keys.forEach((key) => {
            if (key in row) {
                s += "<tr><th>" + esc(key) + "<td>" + esc(row[key]);
            }
        });
    });
    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function rows2keyvalueall(id, unused, data) {
    let s = "<table border=1 cellspacing=0>"
    Object.keys(data).forEach((key) => {
        s += "<tr><th>" + esc(key) + "<td>" + esc(data[key]);
    });

    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function rows2table(id, columns, data) {
    let s = "<table border=1 cellspacing=0>"
    s += "<tr>"
    columns.forEach((col) => {
        s += "<th>" + esc(col)
    });
    data.forEach((row) => {
        s += "<tr>"
        columns.forEach((col) => {
            let val = row[col]
            if (typeof val === "undefined") {
                val = ''
            }
            s += "<td>" + esc(val)
        });
    });

    s += "</table>"
    let div = document.getElementById(id);
    div.innerHTML=s
}

function do_jsonrpc(url, method, params, id, handler, handler_param) {
    let body = {
        "jsonrpc": "2.0",
        "method": method,
        "id": jsonrpc_id,
        "params": params
    }
    jsonrpc_id++;

    fetch(url, {method:'POST', body: JSON.stringify(body)})
      .then(function (response) {
        if (!response.ok) {
            throw new Error('Fetch got ' + response.status)
        }
        return response.json();
      })
      .then(function (data) {
        if ('error' in data) {
            throw new Error('JsonRPC got ' + data['error'])
        }
        handler(id,handler_param,data['result']);
      })
      .catch(function (err) {
        console.log(err);
      });
}

function do_stop() {
    // FIXME: uses global in script library
    do_jsonrpc(
        url, "stop", null,
        'verbose',
        function (id,param,result) {}, null
    );
}

function setverbose(tracelevel) {
    if (tracelevel < 0) {
        tracelevel = 0;
    }
    // FIXME: uses global in script library
    do_jsonrpc(
        url, "set_verbose", [tracelevel],
        'verbose',
        result2verbose, null
    );
}

function refresh_setup(interval) {
    var timer = setInterval(refresh_job, interval);
}
