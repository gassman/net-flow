
function MinMax( array: Array<number>):[number, number] {
	if (array.length == 0) {
		return [0, 0];
	} else {
		let max:number = array[0];
		let min:number = array[0];
		for(let i=0; i < array.length; i++) {
			if (max < array[i]) {
				max = array[i];
			}
			if (min > array[i]) {
				min = array[i];
			}
		}
		return [min, max];
	}
}

function Sum(array: Array<number>):number {
	let result:number = 0
	for( let i=0; i < array.length; i++) {
		result += array[i];
	}
	return result
}

function Mean( array: Array<number>):number {
	let mean = 0.0;
    if (array.length === 0) {
		return 0.0;
	} else {
		mean = (Sum(array)/array.length);
		return mean;
	}
}
// Calculate standard deviation for the values passed in
function StdDev(array: Array<number>): number {
	if(array.length == 0 ){
		return 0.0;
	} else {
		let square = 0.0;

		for( let i=0; i < array.length; i++ ) {
			square += ( array[i] - Mean(array)) * (array[i] - Mean(array));
		}
		return Math.sqrt(square / array.length);
	}
}

export { MinMax, StdDev, Mean, Sum };