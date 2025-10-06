function getTooltipHtml(d) {
    var output = '<b>' + d.name + '</b>';
    if (d.potentiallyremoved == 1) {
        output += "<br/>Potentially deleted";
    }
    if (d.FullEntityName != null) {
        output += '<br/>Entity: ' + d.FullEntityName;
    } else {
        if (d.BU != null) {
            output += '<br/>BU: ' + d.BU;
        }
        if (d.entity != null) {
            output += '<br/>Entity: ' + d.entity;
        }
    }
    if (d.forest != null) {
        output += '<br/>Forest: ' + d.forest;
    }
    if (d.score != null) {
        output += '<br/>Score: ' + d.score;
        output += '<ul>';
        output += '<li>StaleObjects: ' + d.staleObjectsScore;
        output += '<li>Privilegied Group: ' + d.privilegiedGroupScore;
        output += '<li>Trust: ' + d.trustScore;
        output += '<li>Anomaly: ' + d.anomalyScore;
        output += '</ul>';
    }
    return output;
}

var colors = {
    'default': {background: '#CCCCCC', border: '#212121', highlight: {background: '#CCCCCC', border: '#212121' } },
    criticalscore: {background: '#A856AA', border: '#19231a', highlight: {background: '#A856AA', border: '#19231a' } },
    superhighscore: {background: '#E75351', border: '#19231a', highlight: {background: '#E75351', border: '#19231a' } },
    highscore: {background: '#FA9426', border: '#19231a', highlight: {background: '#FA9426', border: '#19231a' } },
    mediumscore: {background: '#FDC334', border: '#19231a', highlight: {background: '#FDC334', border: '#19231a' } },
    lowscore: {background: '#74C25C', border: '#19231a', highlight: {background: '#74C25C', border: '#19231a' } },
    ucriticalscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#A856AA', border: '#19231a' } },
    usuperhighscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#E75351', border: '#19231a' } },
    uhighscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#FA9426', border: '#19231a' } },
    umediumscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#FDC334', border: '#19231a' } },
    ulowscore: {background: '#f3f3f3', border: '#B1B1B1', highlight: {background: '#74C25C', border: '#19231a' } },
    potentiallyremoved: {background: '#dddddd', border: '#a352cc', highlight: {background: '#dddddd', border: '#a352cc' } },
    unknown: {background: '#ffffff', border: '#a352cc', highlight: {background: '#ffffff', border: '#a352cc' } }
};

function reshape(tree) {

    var nodes = [], edges = [], id = [0];
    function toNode(id, n, parentId, parentName, level, direction, nodes, edges) {
        id[0]++;
        var myId = id[0];
        var node = {
            id: myId,
            name: n["name"],
            shortname: n["shortname"],
            FullEntityName: n["FullEntityName"],
            PCEID: n["PCEID"],
            level: level,
            score: n["score"],
            maturityLevel: n["maturityLevel"],
            staleObjectsScore: n["staleObjectsScore"],
            privilegiedGroupScore: n["privilegiedGroupScore"],
            trustScore: n["trustScore"],
            anomalyScore: n["anomalyScore"],
            BU: n["BU"],
            Entity: n["Entity"],
            potentiallyremoved: n["potentiallyremoved"],
        };
        nodes.push(node);
        if (parentId != 0) {
            var edge = {
                source: parentId,
                target: myId,
                rels: [parentName + "->" + n["name"]]
        };
        edges.push(edge);
    }
    if ('children' in n) {
        for (var i = 0; i < n.children.length; i++) {
            var mydirection = direction;
            if (level == 0 && i > n.children.length / 2)
                mydirection = -1;
            toNode(id, n.children[i], myId, n["name"], level + mydirection, mydirection, nodes, edges);
        }
    }
}
toNode(id, tree, 0, "", 0, 1, nodes, edges);
return { nodes: nodes, links: edges };
}

function cartoSelectColor(n) {
    if (n['score'] <= 30) {
        return colors['lowscore'];
    }
    else if (n['score'] <= 50) {
        return colors['mediumscore'];
    }
    else if (n['score'] <= 70) {
        return colors['highscore'];
    }
    else if (n['score'] < 100) {
        return colors['superhighscore'];
    }
    else if (n['score'] == 100) {
        return colors['criticalscore'];
    }
    else if(n['potentiallyremoved'] == 1)
	{
		return colors['potentiallyremoved'];
	}
    else
        return colors['unknown'];
}

function carto(data, hierachicalLayout) {
    var nodes = new vis.DataSet();
    var edges = new vis.DataSet();



    for (var i = 0; i < data.nodes.length; i++) {
        var n = data.nodes[i], node;

        node = {
            // we use the count of the loop as an id if the id property setting is false
            // this is in case the edges properties 'from' and 'to' are referencing
            // the order of the node, not the real id.
            id: n['id'],
            shortName: n['shortname'],
            value: 0 === n.dist ? 10 : 1,
            label: n['shortname'],
            title: getTooltipHtml(n),
            PCEID: n['PCEID'],
            maturityLevel: n["maturityLevel"],
            level: n['level'],
            BU: n['BU'],
            Entity: n['Entity'],
            forest: n['forest'],
            color: cartoSelectColor(n)
        };
        nodes.add(node);
    }
    for (var j = 0; j < data.links.length; j++) {
        var l = data.links[j];
        var edge = {
            from: l.source,
            to: l.target,
            data: {
                rels: l.rels,
                fromShortName: nodes.get(l.source).shortName,
                fromBaseGroup: nodes.get(l.source).baseGroup,
                toShortName: nodes.get(l.target).shortName,
                toBaseGroup: nodes.get(l.target).baseGroup,
                type: l.type
            },
            arrows: l.type === 'double' ? 'to, from' : 'to',
            title: l.rels.join('<br>'),
            color: {color: l.color, highlight: l.color, hover: l.color }
        };

        edges.add(edge);
    }

    // create a network
    var container = document.getElementById('mynetwork');
    var networkData = {
        nodes: nodes,
        edges: edges
    };

    // create an array with nodes
    var options = {
        //height: (window.innerHeight -130) + 'px',
        //width: '100%',
        height: '100%',
        autoResize: true,
        layout:
        {
            improvedLayout: false
        },
        nodes: {
            // you can use 'box', 'ellipse', 'circle', 'text' or 'database' here
            // 'ellipse' is the default shape.
            shape: 'ellipse',
            size: 20,
            font: {
                //size: 15,
                color: '#000000'
                //face: 'arial' // maybe use a monospaced font?
            },
            borderWidth: 1,
            borderWidthSelected: 3,
            scaling: {
                label: {
                    min: 15,
                    max: 25
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
    if (hierachicalLayout) {
        options.layout.hierarchical = { enabled: true, sortMethod: 'directed' };
    } else {
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
    }
    var network = new vis.Network(container, networkData, options);
    network.data = networkData;

    return network;
}

var network;

var data = getData('Data');
var FullNodeMap = getData('FullNodeMap');
if (!FullNodeMap)
{
    data = reshape(data);
}

var loadingModal = new bootstrap.Modal(document.getElementById('loadingModal'));

if (data.nodes.length > 0) {
    loadingModal.show();
}

network = carto(data,!FullNodeMap);

var progressBar = $('#loadingModal .progress-bar');

network.on('stabilizationProgress', function (params) {
    var percentVal = 100 * params.iterations / params.total;
    progressBar.css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
});
network.once('stabilizationIterationsDone', function () {
    var percentVal = 100;
    progressBar.css('width', percentVal + '%').attr('aria-valuenow', percentVal + '%').text(percentVal + '%');
    // really clean the dom element
    setTimeout(function () {
        loadingModal.hide();
    }, 100);
});