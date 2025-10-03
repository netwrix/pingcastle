$(function () {
    $(window).scroll(function () {
        if ($(window).scrollTop() >= 70) {
            $('.information-bar').removeClass('hidden');
            $('.information-bar').fadeIn('fast');
        } else {
            $('.information-bar').fadeOut('fast');
        }
    });
});

document.addEventListener('DOMContentLoaded', function () {

    $('.div_model').on('click', function (e) {
        $('.div_model').not(this).popover('hide');
    });

    new bootstrap.Tooltip(document.body, {
        selector: '.has-tooltip'
    });

    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

});

$('#optionWideScreen').change(function () {
    if (this.checked) {
        $('.container').addClass("container-fluid").removeClass("container");
    } else {
        $('.container-fluid').addClass("container").removeClass("container-fluid");
    }

});

window.addEventListener('beforeprint', function () {
    $('table').bootstrapTable('togglePagination');
});

window.addEventListener('afterprint', function () {
    $('table').bootstrapTable('togglePagination');
});

$('#optionPagination').change(function () {
    $('table').bootstrapTable('togglePagination');
});

$('#optionExpand').change(function () {
    if (this.checked) {
        $('.collapse').addClass("collapse-cancelled").removeClass("collapse");
    } else {
        $('.collapse-cancelled').addClass("collapse").removeClass("collapse-cancelled");
    }
});

function noHtmlSorter(a, b) {
    return strip(a).localeCompare(strip(b));
}

function noHtmlSearch(data, text) {
    if (!text) {
        return data;
    }
    return data.filter(function (row) {
        return Object.entries(row).some(([key, value]) => {
            return (strip(value).indexOf(text) > -1);
        });
    });
}

function strip(html) {
    // Create a new div element
    var temporalDivEl = document.createElement("div");
    // Set HTML content using provider
    temporalDivEl.innerHTML = html;
    // Get the text property of the element (browser support)
    return temporalDivEl.textContent || temporalDivEl.innerText || "";
}

function getData(dataSelect) {
    try {
        var inlineJsonElement = document.querySelector(
            'script[type="application/json"][data-pingcastle-selector="' + dataSelect + '"]'
        );
        var data = JSON.parse(inlineJsonElement.textContent);
        return data;
    } catch (err) {
        console.error('Couldn t read JSON data from ' + dataSelect, err);
    }
}
