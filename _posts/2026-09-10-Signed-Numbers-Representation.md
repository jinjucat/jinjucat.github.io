---
layout: single
title:  "Signed Numbers Representation"
date: 2026-09-10
classes: wide
tags:
  - Digital Logic Design
  - dld
  - Hardware
categories: dld
---
So far we've only added and subtracted positive numbers. But computers don't just work with positive numbers, they need a way to represent negative numbers too, using nothing but 0s and 1s. Today we look at the three classic ways to do that which are Signed Magnitude, One's Complement, and Two's Complement, and understand why hardware designers ultimately settled on the last one. 

In all three representations, we agree on one convention up front that the **leftmost bit** (the Most Significant Bit, or MSB) is reserved to tell us the sign of the number.
- MSB = `0` → the number is positive 
- MSB = `1` → the number is negative
 
![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 08-44-32.png)

So if we're working with 8-bit numbers, we no longer get to use all 8 bits for magnitude as one bit is spent just announcing the sign, and the remaining 7 bits represent the actual value. That's the one idea all three schemes share. Where they differ is how the remaining bits represent negative values.

## Signed Magnitude
This is the most intuitive one. Keep the magnitude which is the actual binary value exactly as it is, and just flip the sign bit to `1` when the number is negative. Let's take 8 bit numbers as our example:

| Decimal | Signed Magnitude |
| ------- | ---------------- |
| +5      | `0000 0101`      |
| -5      | `1000 0101`      |
| +18     | `0001 0010`      |
| -18     | `1001 0010`      |

Notice `+5` and `-5` share the exact same 7 magnitude bits (`000 0101`), the only thing that changed is that leading sign bit. 
### Limitations to Signed Magnitude
Signed Magnitude has two problems that make it a poor fit for hardware:

**Problem 1: Two representations of zero.**

| Decimal | Signed Magnitude |
| ------- | ---------------- |
| +0      | `0000 0000`      |
| -0      | `1000 0000`      |

Mathematically, `+0` and `-0` are the same value, but the hardware now sees two different bit patterns for zero. That wastes a code and forces every comparison circuit to special case it.

Problem 2: Incorrect Addition Results

With unsigned binary, we could just add column by column and be done. With Signed Magnitude, we can't. Try adding `+5` and `-3`:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 12-19-18.png)

If we just add these like ordinary binary numbers, we get `1000 1000`, which reads as `-8` in Signed Magnitude. But `5 + (-3)` should be `+2`, not `-8`! The hardware would first need to compare the signs, figure out which number is bigger, subtract the smaller magnitude from the larger, and then decide the sign of the result separately. That's an entire decision tree of extra logic just to add two numbers which is exactly the kind of complexity we want to avoid in circuit design.
## One's Complement

Signed Magnitude failed on addition because the sign bit and the magnitude bits don't cooperate. One's Complement fixes this with a completely different way to build the negative version of a number and that is to flip every single bit, not just the sign bit.

Before talking about negatives at all, look at what happens when we add any bit to its own flip:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 12-20-23.png)

So a bit plus its own flip always equals 1. Now do this across a whole 8-bit number.
Take `X = 0000 0101` (5) and flip every bit to get `1111 1010`, then add them:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Number_System_GIF_20.gif)

Every column independently lands on `1`, so the total is invariably all 1s. This isn't special to `5` but it is true for any `X`, for the exact same column by column reason. That gives us one solid fact to build on which is true for any X:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 13-09-54.png)

Say we want to compute `7 − 3`, but we're only allowed to add as no subtraction circuit exists. Rearranging the fact above for `X = 3` gives:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 13-12-56.png)

So instead of subtracting 3, try adding `flip(3)`:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 13-28-32.png)

Adding 7 (0000 0111) to 1111 1100:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 13-32-36.png)

Notice the 9th bit. That carry out bit is exactly the leftover `1111 1111` spilling out of the 8-bit box. Drop it as it can't fit in 8 bits and add it back onto what remains. This step is called the **end-around carry**:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Number_System_GIF_21.gif)

This gives us a 4 which is our answer for 7-3.
### So why does flipping bits count as "negative"?

Because `X + flip(X) = 1111 1111`, and One's Complement simply treats all 1s as its zero (Means that for 1's complement we take all 1's like 1111 1111 as a 0). Negative X has always meant, by definition, "the thing that cancels X out to zero when added to it." Flip(X) does exactly that, guaranteed, one column at a time. 

| Decimal | Binary (magnitude) | One's Complement |
| ------- | ------------------ | ---------------- |
| +5      | `0000 0101`        | `0000 0101`      |
| -5      | flip all bits →    | `1111 1010`      |

### Limitations

**Problem 1: Zero, again as in signed magnitude.** One's Complement still has two representations of zero:

| Decimal | One's Complement |
| ------- | ---------------- |
| +0      | `0000 0000`      |
| -0      | `1111 1111`      |

**Problem 2: That end-around carry.** Every addition now needs an extra pass through the adder to fold the carry back in. It works, but it's an extra step that real hardware would rather not have to perform every single time it adds two numbers.

## Two's Complement

Recall where we left one's complement: `flip(X)` isn't the true negative, it is off by a fixed, constant amount (`1111 1111`) every single time. It is predictable, but we had to manually patch it after every addition (the end-around carry). Two's complement asks the question that if the error is always the exact same fixed amount, then why patch it after the fact and why not integrate the fix into the number itself before we ever add anything? So what it does is:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 13-55-14.png)

Just add 1 directly to flip(X) when we create the negative number instead of waiting to add it back in after every single addition. Lets revisit the 5+(-3) example but this time with two's complement.

![diagram](/Tutorials/DLD/Signed_Number_Rep/Number_System_GIF_22.gif)

So the carry which pops out again we just throw it away. 

To build a deeper intuition, we know that if we have a number 5, then that number is always 5 plus 0 on the number line.

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 14-19-07.png)

We know that a number's negative is what makes the  number 0 when added to it. If we come 5 plus the number line it gives us a 5, so if we go 5 back in the number line...

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 14-24-04.png)

then it should technically give us an 11.

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 14-25-51.png)

So if +5 on the number line gives 5 then if we add 11 to 5 that should give us a 0.

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 14-30-00.png)

This question might arise in your mind that why is it safe to just discard the carry this time, when one's complement needed it added back? Because the `+1` we baked in up front already _pre-paid_ the debt that carry represented. In one's complement the carry was telling us that we are still `1111 1111` short of true cancellation so we need to fix it. In two's complement, that shortfall was already covered when we added the `1` at creation time, so the carry now is just genuine overflow out of the register.

## Comparison of Signed Number Representations

Here's the same set of 4-bit numbers represented in all three schemes, so you can see exactly how they diverge:

| Decimal | Signed Magnitude | One's Complement | Two's Complement |
| ------- | ---------------- | ---------------- | ---------------- |
| +7      | `0111`           | `0111`           | `0111`           |
| +3      | `0011`           | `0011`           | `0011`           |
| +0      | `0000`           | `0000`           | `0000`           |
| -0      | `1000`           | `1111`           | —                |
| -3      | `1011`           | `1100`           | `1101`           |
| -7      | `1111`           | `1000`           | `1001`           |
| -8      | —                | —                | `1000`           |

You might've noticed some things....

- Positive numbers look **identical** across all three schemes. The differences shows up on the negative side.
- Two's Complement has no `-0` row, which is the fix we walked through above.
- Two's Complement can represent one extra negative number (`-8`) that the other two can't reach. We'll see why in the range formula below.

## Range of Signed Number Representations

For an `N`-bit number:

|Representation|Range|
|---|---|
|Signed Magnitude|−(2^(n−1) − 1) to +(2^(n−1) − 1)|
|One's Complement|−(2^(n−1) − 1) to +(2^(n−1) − 1)|
|Two's Complement|−(2^(n−1)) to +(2^(n−1) − 1)|

For 8 bits (`n = 8`), that works out to:

| Representation   | Range        |
| ---------------- | ------------ |
| Signed Magnitude | −127 to +127 |
| One's Complement | −127 to +127 |
| Two's Complement | −128 to +127 |

Signed Magnitude and One's Complement both waste a code representing `-0` twice, so they lose one usable value on the negative side compared to how many total bit patterns are actually available. Two's Complement doesn't waste anything on a duplicate zero, so it gets to squeeze one extra negative number (`-128`) out of the same 8 bits. This is a direct, visible consequence of fixing the double zero problem.

## Way to Read a Two's Complement Number

We don't always need to flip and add 1 to find out what a Two's Complement bit pattern means in decimal. Treat the Most Significant Bit as carrying a **negative** place value, and every other bit as its normal positive place value. For an 8-bit number, the place values become:

`-128, 64, 32, 16, 8, 4, 2, 1`

Let's decode `1111 1011`:

![diagram](/Tutorials/DLD/Signed_Number_Rep/Screenshot from 2026-09-10 14-37-12.png)

That matches the `-5` we computed earlier by flipping and adding 1. Same answer, different route. This place value trick is often faster once it clicks, since it skips the flip and add 1 step entirely.
