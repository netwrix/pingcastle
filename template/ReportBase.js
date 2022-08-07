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

});

$('#optionWideScreen').change(function () {
    if (this.checked) {
        $('.container').addClass("container-fluid").removeClass("container");
    } else {
        $('.container-fluid').addClass("container").removeClass("container-fluid");
    }

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
