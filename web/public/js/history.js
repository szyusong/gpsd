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
.controller("historyCtrl", function($scope, $location, $http, bootbox){
	$scope.show_loading = true;
	
	$scope.psn = $location.search().psn;
	$scope.history = [];
	$scope.historyDateCategory = [];
	$scope.dateCategory = "";
	
	$scope.historyClass = function(history){
		return (history.interval && Math.abs(history.interval - 15) >= 10) ? "danger" : "";
	};
	
	$scope.showLoading = function(show) {
		$scope.show_loading = show;
	};
	
	$scope.loadHistory = function(data) {
		var category = {};
		
		$scope.historyDateCategory = [];
		$scope.dateCategory = "";
		
		data.forEach(function(history) {
			var date = history.time.substr(0, 10);
			if ($scope.dateCategory == "") {
				$scope.dateCategory = date;
			}
			if (category.date != date) {
				if (category.count) {
					$scope.historyDateCategory.push(category);
				}
				category = {};
				category.date = date;
				category.count = 1;
			}
			else {
				category.count++;
			}
		});
		if (category.count) {
			$scope.historyDateCategory.push(category);
		}
		$scope.history = data;
		$scope.show_loading = false;
	};
	
	$scope.toDHMS = function(seconds) {
		var day = seconds / 3600 / 24;
		var hour = (seconds / 3600) % 24;
		var minute = (seconds % 3600) / 60;
		var second = seconds % 60;
		return "%d_%02d:%02d:%02d".$(day, hour, minute, second);
	};
	
	// 获取升级历史记录
	$scope.getHistory = function() {
		$http.get("/history", {params: {psn: $scope.psn}})
		.success(function (data) {
			$scope.loadHistory(data);
		})
		.error(function (error) {
		});
	};

	$scope.getHistory();
})
.filter("filterHistory", function() {
	return function(items, dateCategory) {
		var resultArr = [];
		angular.forEach(items, function(item) {
			if (item.time.substr(0, 10) == dateCategory) {
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

