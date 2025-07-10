function xy2d(order, x, y) {
    var d = 0;
    for (var s = order / 2; s > 0; s /= 2) {
        var rx = 0, ry = 0;

        if ((x & s) > 0) rx = 1;
        if ((y & s) > 0) ry = 1;

        d += s * s * ((3 * rx) ^ ry);

        // inlining
        // hilbertRot(s, p, rx, ry)
        if (ry === 0) {
            if (rx === 1) {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            var tmp = x;
            x = y;
            y = tmp;
        }
        // end inline
    }
    return d;
}

function d2xy(order, d)
{
    var rx, ry, s, t = d;
    var x = y = 0;
    for (s = 1; s < order; s *= 2)
    {
        rx = 1 & (t / 2);
        ry = 1 & (t ^ rx);

        // inlining
        // hilbertRot(s, p, rx, ry)
        if (ry === 0) {
            if (rx === 1) {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            var tmp = x;
            x = y;
            y = tmp;
        }
        // end inline

        x += s * rx;
        y += s * ry;
        t /= 4;
    }
    return {x: x, y: y}; 
};

var colorArray = ['#377eb8','#66a61e','#984ea3','#00d2d5','#ff7f00','#af8d00','#7F80cd','#b3e900','#c42e60','#a65628','#F781bf','#8Dd3c7','#bedada','#fb8072','#80b1d3','#fdb462','#fccde5','#bc80bd','#ffed6f'];

var sourceExcluded = [];

function draw()
{
    var canvas = document.getElementById('view');
    var order = canvas.getAttribute('view-order');
    var id = canvas.getAttribute('view-id');
    var ctx = canvas.getContext('2d');
	
    var view = getData('Views').find(function(element) {
        return element.id == id;
    });
    if (view == null)
        return;

    ctx.fillStyle = 'ghostwhite';
    ctx.fillRect(0, 0, order, order);

    ctx.lineWidth = 1;
    ctx.strokeStyle = 'grey';
    if (view.name === '10.0.0.0/8') {
        for (var i = 1; i <= 16; i++) {
            ctx.beginPath();
            ctx.moveTo(0, i * 64);
            ctx.lineTo(order, i * 64);
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(i * 64, 0);
            ctx.lineTo(i * 64, order);
            ctx.stroke();
        }
        ctx.fillStyle = 'grey';
        ctx.textAlign = 'center';
        for (var i = 0; i < 16; i++) {
            for (var j = 0; j < 16; j++) {
                var d = xy2d(order, i * 64 + 32, j * 64 + 32);
                var ipInt = d * (view.end - view.start) / (order * order) + view.start;
                ctx.font = '9px Georgia';
                var ip = (ipInt >>> 24) + '.' + (ipInt >> 16 & 255) + '.0.0/16';
                ctx.fillText(ip, i * 64 + 32, j * 64 + 32);
            }
        }
    }
    if (view.name === '192.168.0.0/16') {
        for (var i = 1; i <= 16; i++) {
            ctx.beginPath();
            ctx.moveTo(0, i * 16);
            ctx.lineTo(order, i * 16);
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(i * 16, 0);
            ctx.lineTo(i * 16, order);
            ctx.stroke();
        }
    }

    document.getElementById('view-scale').textContent = '' + Math.ceil((view.end - view.start) / (order * order));
    document.getElementById('view-name').textContent = view.name;

    var network = getData('Network').filter(function(element) {
        return element.start >= view.start && element.end <= view.end && (element.start != view.start || element.end != view.end) && sourceExcluded.indexOf(element.source) === -1;
    });
    network.sort((a, b) => (a.end - a.start > b.end - b.start) ? -1 : 1);

    var owner = ['_multiple_'];
    network.forEach(function(element) {
        var start = Math.ceil((element.start - view.start) * (order * order)/ (view.end - view.start));
        var end = Math.ceil((element.end - view.start) * (order * order)/ (view.end - view.start));
        var color = 'black';
        if ('domainFQDN' in element && element.domainFQDN !== undefined)
        {
            if (owner.indexOf(element.domainFQDN) == -1)
            {
                owner.push(element.domainFQDN);
            }
            var colorindex = owner.indexOf(element.domainFQDN) % colorArray.length;
            color = colorArray[colorindex];
        }
        for(var i = start; i < end; i++)
        {
            var xy = d2xy(order, i);
            ctx.fillStyle = color;
            ctx.fillRect(xy.x,xy.y,1,1);
        }
    }
	);

    document.getElementById('domain_legend').innerHTML = '';
    var legendFQDN = owner.slice(0);
    legendFQDN.sort();
    for (var i = 0; i < legendFQDN.length; i++) {
        if (legendFQDN[i] === '_multiple_') continue;
        $('#domain_legend').append('<div class="row"><div class="col-lg-1"><canvas id="domain_' + i + '_legend" width="20" height="20"></canvas></div><div class="col-lg-11"><p>Network: ' + legendFQDN[i] + '</p></div></div>');
        var ctx = document.getElementById('domain_' + i + '_legend').getContext('2d');
        ctx.strokeStyle = 'black';
        ctx.strokeRect(0,0,20,20);
        var colorindex = owner.indexOf(legendFQDN[i]) % colorArray.length;
        ctx.fillStyle = colorArray[colorindex];
        ctx.fillRect(1, 1, 18, 18);
    }

    var dc = getData('DC').filter(function(element) {
        return element.iplong >= view.start && element.iplong <= view.end;
    });
    dc.forEach(function(element) {
        var start = Math.ceil((element.iplong - view.start) * (order * order)/ (view.end - view.start));
        var xy = d2xy(order, start);
        ctx.fillStyle = 'red';
        ctx.fillRect(xy.x,xy.y,2,2);
    }
	);
}

function ShowTooltip(target, x, y) {
    var id = target[0].getAttribute('view-id');
    var order = target[0].getAttribute('view-order');
    var d = xy2d(order, x, y);
    var tooltip = target.next();
    var view = getData('Views').find(function (element) {
        return element.id == id;
    });
    var ip = d * (view.end - view.start) / (order * order) + view.start;
    var network = getData('Network').filter(function (element) {
        return element.start >= view.start && element.end <= view.end && (element.start != view.start || element.end != view.end) && element.start <= ip && ip <= element.end && sourceExcluded.indexOf(element.source) === -1;
    });
    target.parent().css('position', 'relative');
    tooltip.css({position: 'absolute', top: y, left: x + 20 });
    tooltip.attr('data-bs-original-title', function (i, val) {
        if (network.length == 0) return 'No network found';
        var data = 'Network:<br>';
        network.forEach(function (element) {
            data += element.source + '<br>';
            data += element.name + '<br>';
            data += element.network + '<br>';
            if (element.description != null)
                data += element.description + '<br>';
            if (element.location != null)
                data += element.location + '<br>';
            if (element.domainFQDN != null)
                data += 'assigned to: ' + element.domainFQDN + '<br>';
        });
        return data;
    });
    tooltip.tooltip('show');
}

$('.map_view').on('mousemove', function (e) {
    var target = $(e.target);
    ShowTooltip(target, e.offsetX, e.offsetY);
});

$('.map_view').on('mouseleave', function(e) {
    var tooltip = $(e.target).next();
    tooltip.tooltip('hide');
});


$('.btn-view').on('click', function (e) {
    var target = $(e.target);
    var id = target[0].getAttribute('view-id');
    var order = target[0].getAttribute('view-order');
    var view = getData('Views').find(function (element) {
        return element.id == id;
    });
    var canvas = document.getElementById('view');
    canvas.setAttribute('view-order', order);
    canvas.setAttribute('view-id', id);
    canvas.setAttribute('width', order);
    canvas.setAttribute('height', order);
    $('#bs-sectionViewer').click();
    draw();
});

$('#bs-sectionDClist').on('shown.bs.tab', function () {

    $('#bs-sectionDClist').off();//to remove the binded event after initial rendering

    $('#dc_list').bootstrapTable({
        pagination: true,
        search: true,
        sortable: true,
        columns: [
            {
                field: 'source',
                sortable: true
            },
            {
                field: 'name',
                sortable: true
            },
            {
                field: 'ip',
                sortable: true
            }],
        data: getData('DC')
    });
});
$('#bs-sectionNetworklist').on('shown.bs.tab', function () {

    $('#bs-sectionNetworklist').off();//to remove the binded event after initial rendering

    $('#network_list').bootstrapTable({
        pagination: true,
        search: true,
        sortable: true,
        columns: [
            {
                field: 'source',
                sortable: true
            },
            {
                field: 'name',
                sortable: true
            },
            {
                field: 'network',
                sortable: true
            },
            {
                field: 'description',
                sortable: true
            },
            {
                field: 'domainFQDN',
                sortable: true
            }],
        data: getData('Network')
    });
});

$('#bs-sectionViewer').on('shown.bs.tab', function () {

    $('#bs-sectionViewer').off();//to remove the binded event after initial rendering

    draw();
});

function initLegend(){
    var ctx = document.getElementById('dc_legend').getContext('2d');
    ctx.strokeStyle = 'black';
    ctx.strokeRect(0,0,20,20);
    ctx.fillStyle = 'red';
    ctx.fillRect(9,9,2,2);

    ctx = document.getElementById('empty_legend').getContext('2d');
    ctx.strokeStyle = 'black';
    ctx.strokeRect(0,0,20,20);
    ctx.fillStyle = 'ghostwhite';
    ctx.fillRect(1, 1, 18, 18);

    ctx = document.getElementById('filled_legend').getContext('2d');
    ctx.fillStyle = 'black';
    ctx.fillRect(0,0,20,20);
}

initLegend();

function initFilter() {
    var network = getData('Network');
    var fqdnFilter = [];
    network.forEach(function (element) {
        if (fqdnFilter.indexOf(element.source) === -1) {
            fqdnFilter.push(element.source);
        }
    });
    fqdnFilter.sort();
    $('#accordionFilter').empty();
    for (var i = 0; i < fqdnFilter.length; i++) {
        $('#accordionFilter').append('<div class="row"><div class="col-lg-12"><div class="custom-control custom-switch"><input value="1" id="filter' + i + '" class="custom-control-input" type="checkbox" checked="checked" filter-source="' + fqdnFilter[i] + '"><label class="custom-control-label" for="filter' + i + '">Enable source: ' + fqdnFilter[i] + '</label></div></div></div>');

        $('#filter' + i).change(function () {
            // this will contain a reference to the checkbox   
            if (this.checked) {
                for (var j = 0; j < sourceExcluded.length; j++) {
                    if (sourceExcluded[j] === this.getAttribute('filter-source')) {
                        sourceExcluded.splice(j, 1);
                    }
                }
            } else {
                sourceExcluded.push(this.getAttribute('filter-source'));
            }
            draw();
        });
    }
}
initFilter();

$('#InputIpMap').keyup(function (e) {
    var val = $(this).val();
    if (val == '') {
        $('#validationfeedback').removeClass('d-block');
        $('#validationfeedback').html('');
        return;
    }
    var ipVal = val.split('.').reduce(function (ipInt, octet) { return (ipInt << 8) + parseInt(octet, 10); }, 0) >>> 0;

    var viewjq = $('#view');

    var id = viewjq[0].getAttribute('view-id');
    var order = viewjq[0].getAttribute('view-order');
    var view = getData('Views').find(function (element) {
        return element.id == id;
    });
    if (ipVal < view.start || ipVal > view.end) {
        $('#validationfeedback').addClass('d-block');
        $('#validationfeedback').html('Ip address ' + val + ' not in range ' + view.name);
        return;
    }
    $('#validationfeedback').removeClass('d-block');
    $('#validationfeedback').html('');
    var d = (ipVal - view.start) * (order * order) / (view.end - view.start);
    var xy = d2xy(order, d);
    ShowTooltip(viewjq, xy.x, xy.y);
});
