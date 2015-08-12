// http://stackoverflow.com/questions/610406/javascript-equivalent-to-printf-string-format
String.form = function(str, arr) {
    var i = -1;
    function callback(exp, p0, p1, p2, p3, p4) {
        if (exp=='%%') return '%';
        if (arr[++i]===undefined) return undefined;
        var exp  = p2 ? parseInt(p2.substr(1)) : undefined;
        var base = p3 ? parseInt(p3.substr(1)) : undefined;
        var val;
        switch (p4) {
            case 's': val = arr[i]; break;
            case 'c': val = arr[i][0]; break;
            case 'f': val = parseFloat(arr[i]).toFixed(exp); break;
            case 'p': val = parseFloat(arr[i]).toPrecision(exp); break;
            case 'e': val = parseFloat(arr[i]).toExponential(exp); break;
            case 'x': val = parseInt(arr[i]).toString(base?base:16); break;
            case 'd': val = parseFloat(parseInt(arr[i], base?base:10).toPrecision(exp)).toFixed(0); break;
        }
        val = typeof(val)=='object' ? JSON.stringify(val) : val.toString(base);
        var sz = parseInt(p1); /* padding size */
        var ch = p1 && p1[0]=='0' ? '0' : ' '; /* isnull? */
        while (val.length<sz) val = p0 !== undefined ? val+ch : ch+val; /* isminus? */
       return val;
    }
    var regex = /%(-)?(0?[0-9]+)?([.][0-9]+)?([#][0-9]+)?([scfpexd])/g;
    return str.replace(regex, callback);
}

String.prototype.$ = function() {
    return String.form(this, Array.prototype.slice.call(arguments));
}

angular.module("gpsApp")
.controller("logCtrl", function($scope, $location){
	var socket = io();
	
	$scope.paused = false;
	$scope.log = "";
	$scope.psn = $location.search().psn;
	
	socket.on('connect', function () {
		socket.emit('device', {psn: $scope.psn});	
	});	
	
	socket.on('gps', function (data) {
		var log = '[%s] longitude: %d latitude: %d altitude: %d speed: %d azimuth: %d'.$(data.time, 
			data.longitude, data.latitude, data.altitude, data.speed, data.azimuth);
		if (!$scope.paused) {
			$scope.log = log + '\r\n' + $scope.log;
			$scope.$apply();
		}
	});	
});
