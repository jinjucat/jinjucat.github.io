
## Introduction

We are going to discuss a very important topic today that is Number system conversions. Before diving in, here's the map of everything we're about to cover:
![[Pasted image 20260909131604.png]]

The three core techniques we will be using in this post are:

1. **Repeated division** (going _from_ decimal _to_ any other base)
2. **The "weight" trick** (going _from_ any other base back _to_ decimal)
3. **Bit-grouping** (converting directly between binary, octal, and hex)
These three techniques will apply to every conversion we do.
## Starting From Decimal

## Decimal to Binary (Repeated Division by 2)

To convert a decimal number into binary, repeatedly divide by 2, and keep track of the **remainder** at each step. The remainders, read from **bottom to top**, give you the binary number.
### Working
Every number can be written as a sum of powers of 2 and that is basically the whole idea behind place value in binary. Repeated division is just a mechanical way of peeling off those powers of 2, one bit at a time, starting with whether the number is even or odd (which tells you the last bit), then working up.

Lets take an example of converting the decimal number 156 to binary.
![[Pasted image 20260909131825.png]]
Now read the remainders **bottom to top**: `1 0 0 1 1 1 0 0`
So **156 (decimal) = 10011100 (binary)**

Let's verify using the place-value method (which we'll formally cover in section 1.2):
![[Pasted image 20260909132059.png]]
128 + 16 + 8 + 4 = **156** which is correct.

Lets take an example of the decimal number 27 and try to build intuition using it. What we know is that every number can be written as a sum of powers of 2, similarly the inverse should also exist, that we _can_ do ordinary division by 2 to get a number's binary equivalent. The question is why does the remainder of that repetitive ordinary division by 2 happen to equal the sequence of bits that makes our binary equivalent of our decimal number, which in this case is 27?

Lets prove this by dividing the our number 27 repetitively by 2. 
![[Pasted image 20260909132157.png]]
This can also be written as:
![[Pasted image 20260909132249.png]]
Notice each row is in the following way:
![[Pasted image 20260909132311.png]]
Now substitute each quotient with what it equals from the row below it, like we will substitute equation b in equation a's quotient. Equation 'a' will become:
![[Pasted image 20260909132351.png]]
Replace `6` using the third equation (`6 = 2×3 + 0`):
![[Pasted image 20260909132421.png]]
Replace `3` using the fourth equation (`3 = 2×1 + 1`):
![[Pasted image 20260909132445.png]]

Replace `1` using the fifth equation (`1 = 2×0 + 1`):
![[Pasted image 20260909132500.png]]

Notice how this is giving us a high bit 1 for some powers of 2 and giving us a low bit 0 for the rest. Lets drop the `32×0`  as its a leading 0 and hence won't matter and look at what's left:
![[Pasted image 20260909132521.png]]
Look at the coefficients in that final line `1, 1, 0, 1, 1`. Those are exactly our five remainders and they landed in exact order against 16, 8, 4, 2, 1. Every time we substituted a quotient equation into the one above it, the remainder from that row got multiplied by one more factor of 2 (because it was sitting inside a `2×(...)`, pushing it one column to the left. The _last_ remainder found (from the row closest to 0) ends up multiplied by the _most_ factors of 2, landing in the highest column. The first remainder found ends up with zero extra factors of 2, landing in the ones column. This is a concept we will soon visit again!

## Binary to Decimal ("Weight" Method)

This is the reverse direction, and it's the method you already know from our earlier posts. Write the power of 2 headers above each bit, and add up the headers wherever there's a `1`.

As an example lets convert`10011100` to decimal:

![[Pasted image 20260909132751.png]]
Add the columns with a 1 which give us 128 + 16 + 8 + 4 = **156**.

This confirms our division result above. The two methods are exact mirror images of each other. Division peels off bits from the bottom, while place value expansion reconstructs the number by adding weighted columns.

## Decimal to Octal (Repeated Division by 8)

Same intuition as decimal to binary, but now divide by 8 instead of 2, since octal digits run from 0–7 and the base is 8. Lets take 156 as an example to understand this. As an example lets convert 156 (decimal) to octal.

Same substitution trick, we write each row as "dividend = 8×quotient + remainder":

![[Pasted image 20260909132926.png]]
Now substitute upward, starting from the top:
![[Pasted image 20260909132947.png]]

Replace `19` using the second equation (`19 = 8×2 + 3`):
![[Pasted image 20260909133000.png]]

Distribute the 8 across both terms inside the parentheses:
![[Pasted image 20260909133018.png]]

Replace `2` using the third equation (`2 = 8×0 + 2`):
![[Pasted image 20260909133030.png]]
Now distribute the 64:
![[Pasted image 20260909133048.png]]
You might be thinking why the BODMAS rule is not being followed here. It's because multiplication lets you regroup which pair you multiply first, and you'll always get the same answer. That's the associative law: `a×(b×c) = (a×b)×c`. Now drop the `512×0` term since its a leading zero:
![[Pasted image 20260909133105.png]]

The coefficients 2, 3, 4 are our three remainders, in the exact order we found them, and will now sit against columns 64, 8, 1 which are exactly the powers of 8 (8², 8¹, 8⁰). So the answer is 234.

## Octal to Decimal (Place-Value Method)

Again it is the same weight adding idea, but now the column headers are powers of 8 `..., 512, 64, 8, 1`. As an example lets convert `234` (octal) to decimal
![[Pasted image 20260909133229.png]]

![[Pasted image 20260909133302.png]]
## Decimal to Hex (Repeated Division by 16)

Same trick of repetitive division but this time with base 16. Write each row as:
dividend = 16×quotient + remainder:
![[Pasted image 20260909133351.png]]

Only two rows this time, so there's just one substitution.
![[Pasted image 20260909133405.png]]
Replace `9` using the second equation (`9 = 16×0 + 9`):
![[Pasted image 20260909133417.png]]
Distribute the 16 across both terms inside the parentheses:
![[Pasted image 20260909133433.png]]
Drop the `256×0` term (it's zero):
![[Pasted image 20260909133447.png]]
Look at the coefficients 9 and 12. Those are our two remainders, in the exact order we found them, sitting against columns 16 and 1, with the powers of 16 (16¹, 16⁰). So our answer would be 0x9C.
## Hex to Decimal (Place Value Method)

Notice a pattern across the conversions above that every "into decimal" direction uses the same place value weighting idea, and every "out of decimal" direction uses the same repeated division idea only the divisor (2, 8, or 16) changes. Column headers are now powers of 16 such as `..., 4096, 256, 16, 1`.

### Example: Convert `9C` (hex) to decimal

![[Pasted image 20260909133636.png]]

![[Pasted image 20260909133714.png]]

## Starting From Binary

We've already covered all decimal conversions above. Now let's connect binary directly to octal and hex, without going through decimal at all and this is going to be super easy!

## Binary to Octal (Group in 3s)
Since 8 = 2³, every group of exactly **3 bits** corresponds to exactly one octal digit. To convert binary to octal:
1. Starting from the right, split the binary number into groups of 3 bits.
2. Pad the leftmost group with extra 0s if it doesn't have a full 3 bits.
3. Convert each 3-bit group to its octal digit using the 4-2-1 trick.

As an example lets convert `10011100` (binary) to octal


![[Number_System_GIF_15.gif]]

Now convert each group using 4-2-1:

- `010` → 4-2-1 breakdown: 0+2+0 = **2**
- `011` → 4-2-1 breakdown: 0+2+1 = **3**
- `100` → 4-2-1 breakdown: 4+0+0 = **4**

Result: 234 (octal). Notice we just did the grouping and a quick lookup.
## Octal to Binary (Expand Each Digit to 3 Bits)

This is simply the reverse: take each octal digit and expand it into its 3-bit binary equivalent, then string them together.
### Example: Convert `234` (octal) to binary

- `2` → `010`
- `3` → `011`
- `4` → `100`

Concatenate: them together`010 011 100` and drop the leading padding zero. 
![[Number_System_GIF_16.gif]]
Result: 10011100
## Binary to Hex (Group in 4s)

Since 16 = 2⁴, every group of exactly **4 bits** (a "nibble") corresponds to exactly one hex digit. Same process as octal, just grouping by 4 instead of 3. As an example lets convert `10011100` (binary) to hex.

![[Number_System_GIF_17.gif]]
## Hex to Binary (Expand Each Digit to 4 Bits)

This time we will go in the reverse direction by expanding each hex digit into its 4-bit binary form and then later concatenate. As an example lets convert `9C` (hex) to binary.
![[Number_System_GIF_18.gif]]
- `9` → `1001`
- `C` (12) → `1100`

Concatenate: **10011100 (binary)**

## Starting From Octal

We've covered octal ↔ decimal and octal ↔ binary. The only direction left is octal ↔ hex directly.

## Octal to Hex (Via Binary as a Bridge)

There's no clean direct grouping between octal (3-bit groups) and hex (4-bit groups), because 3 and 4 don't share a simple relationship the way each does with binary. So the standard method is to **convert octal to binary and then binary to hex**, using binary as the universal "bridge" language. As an example lets convert 234 (octal) to hexadecimal.

**Step 1: Octal to binary** (expand each digit to 3 bits, as in section 2.2):

- `2` → `010`
- `3` → `011`
- `4` → `100`

Concatenated: `010011100`

**Step 2: Drop unnecessary leading zeros.**  Dropping it gives us the true binary value: `10011100`.

**Step 3: Binary to hex** (group into 4s from the right, as in section 2.3):

```
1001 1100
```

- `1001` = **9**
- `1100` = **C**

Result: **9C (hex)**
![[Number_System_GIF_19.gif]]

We have seen that going through binary is necessary because 3-bit and 4-bit groupings don't line up neatly with each other, so binary acts as the common "translator" between octal and hex, the same way you might translate French to Spanish via English if you didn't speak both directly.

## Hex to Octal (Via Binary as a Bridge)

Same idea but this time we go from hexadecimal to binary and then binary to octal.
### Example: Convert `9C` (hex) to octal

**Step 1 — Hex to binary** (expand each digit to 4 bits):
- `9` → `1001`
- `C` → `1100`

Concatenated: `10011100`
**Step 2 — Binary to octal** (group into 3s from the right, padding the leftmost group):

```
10 011 100  →  pad leftmost since it doesn't have 3 bits  →  010 011 100
```

- `010` = **2**
- `011` = **3**
- `100` = **4**

Result: **234 (octal)**

# PART 4: The Complete Picture

## 4.1 Choosing the Right Method

| Conversion Direction         | Best Method                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| Decimal → (Binary/Octal/Hex) | Repeated division by 2, 8, or 16                                  |
| (Binary/Octal/Hex) → Decimal | Place-value weighting (multiply each digit by its column's power) |
| Binary ↔ Octal               | Group/expand in 3s                                                |
| /Binary ↔ Hex                | Group/expand in 4s                                                |
| Octal ↔ Hex                  | Bridge through binary (no direct shortcut)                        |

## 4.2 Quick Reference: Powers Used by Each Base

| Base         | Powers (right to left)           |
| ------------ | -------------------------------- |
| Binary (2)   | 1, 2, 4, 8, 16, 32, 64, 128, ... |
| Octal (8)    | 1, 8, 64, 512, ...               |
| Decimal (10) | 1, 10, 100, 1000, ...            |
| Hex (16)     | 1, 16, 256, 4096, ...            |

## 6. Quick Recap for Your Students

- There are really only **three techniques** in this entire post: repeated division (to leave decimal), place-value weighting (to return to decimal), and bit-grouping (to move directly between binary, octal, and hex).
- **Decimal → any base:** divide repeatedly by that base (2, 8, or 16), and read the remainders bottom to top.
- **Any base → decimal:** multiply each digit by its column's power of that base, and add them up (this is the "8-4-2-1"-style trick generalized to any base).
- **Binary ↔ Octal:** group/expand in sets of **3** bits, since 8 = 2³.
- **Binary ↔ Hex:** group/expand in sets of **4** bits, since 16 = 2⁴.
- **Octal ↔ Hex:** there's no direct shortcut. Convert through binary as a bridge, since binary is the "common language" both octal and hex are built from.
- Always sanity-check your work: if you convert a number two different ways (e.g., decimal→octal directly, versus decimal→binary→octal), you should land on the identical answer both times. This is one of the best ways to catch arithmetic mistakes.
