$(document).ready(function() {
    
    $('.testIssue p').each(function() {
        var trigger = $(this), el = trigger.parent().next('.issueEntry');
        trigger.click(function(){
            positionPopup(el.html(), "Traceback");
            $(this).css("color", "#5f2580");
        });
    });
    $('.tdCaseId p a').click(function() {
        $(this).css("color", "#5f2580");
    })
});

//position the popup at the center of the page
function positionPopup(cont, title){

    var winW = 640, winH = 480;
    if (document.body && document.body.offsetWidth) {
        winW = document.body.offsetWidth;
        winH = document.body.offsetHeight;
    }
    if (document.compatMode=='CSS1Compat' && document.documentElement && document.documentElement.offsetWidth ) {
        winW = document.documentElement.offsetWidth;
        winH = document.documentElement.offsetHeight;
    }
    if (window.innerWidth && window.innerHeight) {
        winW = window.innerWidth;
        winH = window.innerHeight;
    }
    winW = winW * 0.95;
    winH = winH * 0.95;
    $.window({
            showModal: true,
            width: winW,
            height: winH,
            y: 10,
            x: 10,
            maxWidth: -1,
            maxHeight: -1,
            scrollable: true,
            maximizable: false,
            minimizable: false,
            modalOpacity: 0.5,
            title: title,
            content: cont,
            footerContent: "..."
    });
}

function getDate(value) {
    var created = new Date();
    var month = created.getMonth() + 1;
    var day = created.getDay();
    var year = created.getFullYear();

    if (month < 10)
        month = "0" + month;
    if (day < 10)
        day = "0" + day;

    return year + "-" + month + "-" + day
}

