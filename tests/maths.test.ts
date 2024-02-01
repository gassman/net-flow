import * as math from "../src/maths";

test('successfully calculates sum', () => {
    const tesData = [1,2,3];
    const test = math.Sum(tesData);
    expect(test).toBe(6);
});

test('successfuly calculates mean value', () => {
    const tesData = [1,2,3];
    const test = math.Mean(tesData);
    expect(test).toBe(2);
});

test('successfuly calculates standard deviation value', () => {
    const tesData = [1,2,3];
    const test = math.StdDev(tesData);
    expect(test).toBeCloseTo(0.8164965);
});

test('successfuly calculates minimum and maximum values', () => {
    const tesData = [1,2,3];
    const [min,max] = math.MinMax(tesData);
    expect(min + max).toBe(4);
});