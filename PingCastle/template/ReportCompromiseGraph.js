
var relationDescription = null;

function cartocp(data, id) {
    var nodes = new vis.DataSet();
    var edges = new vis.DataSet();

    var ignoredNode = [];
    var ignoreContainer = false;
    var hierarchical = false;

    function getTooltipHtml(d) {
        var output = '<span class="font-weight-bold">' + d.shortName + '</span>';
        output += '<br/>' + d.name;
        if (d.type != null)
            output += '<br/>type: ' + d.type;
        if (d.suspicious == 1)
            output += '<br/><span class="unticked">suspicious</span>';
        return output;
    }

    var colors = {
        'default': { background: "#CCCCCC", border: "#212121", highlight: { background: "#CCCCCC", border: "#212121" } },
        suspicious: { background: "#ff6a00", border: "#f12828", highlight: { background: "#ff6a00", border: "#f12828" } },
        critical: { background: "#f12828", border: "#f12828", highlight: { background: "#f12828", border: "#f12828" } },
        user: { background: "#80b2ff", border: "#0047b2", highlight: { background: "#80b2ff", border: "#0047b2" } },
        inetorgperson: { background: "#80b2ff", border: "#0047b2", highlight: { background: "#80b2ff", border: "#0047b2" } },
        foreignsecurityprincipal: { background: "#ffa366", border: "#8f3900", highlight: { background: "#ffa366", border: "#8f3900" } },
        computer: { background: "#d65c33", border: "#661a00", highlight: { background: "#d65c33", border: "#661a00" } },
        group: { background: "#70db70", border: "#196419", highlight: { background: "#70db70", border: "#196419" } },
        organizationalunit: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        container: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        configuration: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        certificationauthority: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        domaindns: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        builtindomain: { background: "#cccccc", border: "#333333", highlight: { background: "#cccccc", border: "#333333" } },
        grouppolicycontainer: { background: "#ad8533", border: "#403100", highlight: { background: "#ad8533", border: "#403100" } },
        gpodirectory: { background: "#e680ff", border: "#8e00b2", highlight: { background: "#e680ff", border: "#8e00b2" } },
        file: { background: "#e680ff", border: "#8e00b2", highlight: { background: "#e680ff", border: "#8e00b2" } },
        unknown: { background: "#ffffff", border: "#a352cc", highlight: { background: "#ffffff", border: "#a352cc" } },
    };
    var symbols = {
        'default': '-',
        user: 'u',
        inetorgperson: 'u',
        foreignsecurityprincipal: 'w',
        computer: 'm',
        group: 'g',
        organizationalunit: 'o',
        container: 'o',
        domaindns: 'o',
        builtindomain: 'o',
        certificationauthority: 'o',
        configuration: 'o',
        grouppolicycontainer: 'x',
        gpodirectory: 'f',
        file: 'f',
        unknown: '?',
    };

    var ignoredClasses = ['organizationalunit', 'container', 'domaindns', 'builtindomain'];


    function edgeTitle(l) {
        var title = '';
        if (relationDescription == null) {
            relationDescription = getData('RelationTypeDescription');
        }
        l.rels.forEach(function (item) {
            title += '<span class="text-uppercase font-weight-bold">' + item + '</span><br>';
            if (relationDescription[item] !== undefined) {
                title += relationDescription[item] + '<br>';
            }
        });
        return title;
    }

    ignoreContainer = $('#switch-1-' + id).is(':checked');

    hierarchical = $('#switch-2-' + id).is(':checked');

    for (var i = 0; i < data.nodes.length; i++) {
        var n = data.nodes[i], node;
        if (ignoreContainer && n['id'] != 0 && ignoredClasses.includes(n['type'])) {
            ignoredNode[n['id']] = {to: []};
            continue;
        }
        node = {
            id: n['id'],
            shortName: n['shortName'],
            suspicious: n['suspicious'],
            value: null === n['dist'] ? 50 : ( n['critical'] == 1 ? 25 : 1),
            label: (n['type'] in symbols ? symbols[n['type']] : symbols['unknown']),
            level: n['dist'],
            title: getTooltipHtml(n),
            shape: null === n['dist'] ? 'box':'ellipse',
            color: n['critical'] == 1 ? colors['critical'] :(n['suspicious'] == 1 ? colors['suspicious'] : (n['type'] in colors ? colors[n['type']] : colors['unknown']))
        };
        nodes.add(node);
    }
    for (var j= 0; j < data.links.length; j++) {
        var l = data.links[j];
			
        if (ignoredNode[l.source] !== undefined)
        {
            ignoredNode[l.source].to.push(l.target);
        }
    }
    for (var j = 0; j < data.links.length; j++) {
        var l = data.links[j];
        if (ignoredNode[l.source] !== undefined) {
            continue;
        }
        if (ignoredNode[l.target] !== undefined) {
            var cont = [l.target];
            while(cont.length != 0)
            {
                var i = cont.pop(cont);
                if (ignoredNode[i] !== undefined) {
                    ignoredNode[i].to.forEach(function(item) {cont.push(item);});
                } else
                {
                    var edge = {
                        from: l.source,
                        to: i,
                        data: {
                            rels: l.rels,
                            type: l.type
                        },
                        arrows: l.type === 'double' ? 'to, from' : 'to',
                        title: edgeTitle(l),
                        color: {color: l.color, highlight: l.color, hover: l.color }
                    };

                    edges.add(edge);
                }
            }
        } else {
            var edge = {
                from: l.source,
                to: l.target,
                data: {
                    rels: l.rels,
                    type: l.type
                },
                arrows: l.type === 'double' ? 'to, from' : 'to',
                title: edgeTitle(l),
                color: {color: l.color, highlight: l.color, hover: l.color }
            };

            edges.add(edge);
        }
    }

    // create a network
    var container = document.getElementById('mynetwork' + id);
    var networkData = {
        nodes: nodes,
        edges: edges
    };

    // create an array with nodes
    var options = {
        height: '100%',
        autoResize: true,
        layout:
        {
        },
        nodes: {
            // you can use 'box', 'ellipse', 'circle', 'text' or 'database' here
            // 'ellipse' is the default shape.
            size: 20,
            font: {
                //size: 15,
                color: '#000000',
                //face: 'arial' // maybe use a monospaced font?
            },
            borderWidth: 1,
            borderWidthSelected: 3,
            scaling: {
                label: {
                    min: 15,
                    max: 50
                }
            }
        },
        edges: {
            width: 2,
            smooth: {
                type: 'continuous'
            },
            hoverWidth: 2,
            selectionWidth: 2,
            arrows: {
                to: {
                    enabled: true,
                    scaleFactor: 0.5
                }, from: {
                    enabled: false,
                    scaleFactor: 0.5
                }
            },
            color: {
                //      inherit: 'from',
                color: '#666666',
                hover: '#333333',
                highlight: '#000000'
            }
        },
        interaction: {
            multiselect: true,
            hover: true,
            hideEdgesOnDrag: true
        }
    };

    if (hierarchical) {
        options.layout =
            {
                //improvedLayout: false,
                hierarchical: { enabled: true, sortMethod: 'directed', direction: 'LR' }
            };
    }

    options.physics = {
        stabilization: {
            iterations: 2000 // try to stabilize the graph in 2000 times, after that show it anyway
        },
        barnesHut: {
            gravitationalConstant: -2000,
            centralGravity: 0.1,
            springLength: 95,
            springConstant: 0.04,
            damping: 0.09
        },
        enabled: true
    };
                        
    var network = new vis.Network(container, networkData, options);
    network.data = networkData;

    return network;
}

function RefreshMap(id) {

    var network;

    var data = getData('Data_' + id);
    var progressBar = $('#progress' + id);
    if (data.nodes.length > 0)
        progressBar.removeClass('d-none');

    network = cartocp(data,id);
	
	var hierarchical = $('#switch-2-' + id).is(':checked');
	if (hierarchical)
	{
		network.on('stabilizationIterationsDone', function(){
			network.setOptions( { physics: false } );
		});
	}
    network.on('stabilizationProgress', function (params) {
        var percentVal = 100 * params.iterations / params.total;
        progressBar.find('.progress-bar').css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
    });
    network.once('stabilizationIterationsDone', function () {
        var percentVal = 100;
        progressBar.find('.progress-bar').css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
        // really clean the dom element
        progressBar.addClass('d-none');
    });
}

$("[id^='switch-']").change(function (event) {
    var id = event.target.id.substring('switch-'.length + 2);
    RefreshMap(id);
});

$("[id^='mcg-']").on('shown.bs.modal', function (event) {
    var id = event.target.id.substring('mcg-'.length);
    location.hash = 'mcg-' + id;
    if(document.getElementById('mynetwork' + id).childNodes.length != 0)
        return;
    RefreshMap(id);

});

$("[id^='mcg-']").on('hide.bs.modal', function (event) {
    // Remove the # from the hash, as different browsers may or may not include it
    var hash = location.hash.replace('#','');

    if(hash != ''){
        // Clear the hash in the URL
        location.hash = '';
    }
});

document.addEventListener('DOMContentLoaded', function () {
    var hash = location.hash.replace('#','');
    if(hash != '' && hash.startsWith('mcg-') ){
        var modalDialog = new bootstrap.Modal(document.getElementById('hash'));
        modalDialog.show();
    }
});
