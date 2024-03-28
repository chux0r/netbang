package uglynum
/********************************************************************************
NumStringToInt32()

Input: A string, expectedly some representation of a portnum integer 0-65535
Output: The int32 value represented by the string and boolean validation that

	it was a valid integer (TRUE); OR
	The first out-of-bounds character that showed the input to be NaN, and
	boolean FALSE.

Examples: Input: "132"  [0x31,0x33,0x32]         Output: 132 [0x84],true

	      Input: "test" [0x74,0x65,0x73,0x74]    Output: 116 [0x74],false
		  Input: "7-23" [0x37,0x2D,0x32,0x33]    Output: 45  [0x2D],false

Q&A time:
Q: HEY! We're doing port math with uint16 numbers, why is this defaulting to
int32? (Great question.)
A: Since other runes may sneak in, including erroneous input or valid list
names, and since we use "-48d (-0x30)" subtraction to convert the Ascii
representationof a number to an actual number, negative int values are possible
and must be handled as signed to prevent bad validation resulting from unsigned
wraparound. That is why this uses int32 and not uint16. We can recast after
we're done farting around.
********************************************************************************/
import (
	"strings"
)

func NumStringToInt32(sn string) (int32, bool) {
	var tot int32 = 0
	isnum := false               // I'll believe you're supposed to be a number when you show me you behave like one...
	sn = strings.TrimSpace(sn) // be nice and trim it up, just in case
	// fmt.Println("\nItem: ", []byte(sn)) //TEST
	slen := len([]rune(sn))
	for i := slen - 1; i >= 0; i-- { // build the number, by walking the chars
		char := sn[i]
		if (int32(char)-48) < 0 || (int32(char)-48) > 9 { // if char is not 0-9
			//fmt.Printf("Char is OOB! c[0x%x] d[%d]", char, int32(char)-48) TEST
			return int32(char), false // return OOB/NaN char value + FALSE
		} else {
			// fmt.Printf("Num char is %c", char) // TEST
			isnum = true
			// Use positional exponent math to compute value.
			// This is, if I am thinking about this correctly, computationally less expensive than using math.Pow10 and float64s :)
			var mult int32 = 1 // multiplier, to rebuild our port num piece by piece
			if char != '0' {   // only when we have a non zero num to compute
				digit := slen - 1 - i // len-1-i is most signif. digit L->R
				for j := digit; j > 0; j-- {
					mult = mult * 10
				}
				// fmt.Printf(" times %d (x10^%d)", mult, digit) TEST
				tot = tot + (int32(char)-48)*mult
				// fmt.Printf(", totaling %d\n", tot)
			}
		}
	}
	return tot, isnum
}