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
.controller("devicesCtrl", function($scope, $http, bootbox){
	$scope.data = {};
	$scope.show_loading = true;
	
	$scope.encodeURI = function(uri) {
		return escape(uri);
	};

	$scope.intervalClass = function(device){
		return (device.interval && (device.interval > 60)) ? "danger" : "";
	};

	$scope.toDHMS = function(seconds) {
		var day = seconds / 3600 / 24;
		var hour = (seconds / 3600) % 24;
		var minute = (seconds % 3600) / 60;
		var second = seconds % 60;
		return "%d_%02d:%02d:%02d".$(day, hour, minute, second);
	};
	
	$scope.showLoading = function(show) {
		$scope.show_loading = show;
	};
	
	$scope.loadDevices = function(data) {
		$scope.devices = data;
		$scope.show_loading = false;
	};
	
	// 获取设备列表
	$scope.getDevices = function() {
		$http.get("/devices")
		.success(function (data) {
			$scope.loadDevices(data);
		})
		.error(function (error) {
		});
	};

	$scope.getDevices();
})
.filter("filterDevice", function() {
	return function(items, search) {
		var resultArr = [];
		angular.forEach(items, function(item) {
			if (item.dev_id.match(search) || 
				item.time.match(search) ||
				item.version.match(search)) {
				resultArr.push(item);
			}
		});
		return resultArr;
	}
})
.directive('onRepeatDone', function() {
	return function(scope, element, attrs) {
		if (scope.$last) 
			scope.$eval(attrs.onRepeatDone);
	};
});

