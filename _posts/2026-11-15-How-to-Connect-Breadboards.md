---
layout: single
title:  "How to Connect Breadboards"
categories: [Digital Logic Design]
date: 2026-11-15
classes: wide
tags:
  - Digital Logic Design
  - dld
  - Hardware
---

One breadboard is often not enough for a bigger circuit. The good news is that breadboards are made to be joined together, and you can share the same power supply between them.  For this you will need:
- 2 breadboards 
- Power supply already connected to the first breadboard 
- 2 jumper wires 
- 1 LED (for testing) 
- 1 resistor (220 Ω works well, anything up to 1 kΩ is fine) 

### Step 1- Join the two breadboards
  Look at the sides of your breadboards. On one side you will see small tabs sticking **out**, and on the other side you will see slots going **in**. They are made to fit each other, just like puzzle pieces or building blocks.

![diagram](/assets/images/HTCB/HTCB1.png)

you are going to fit them together.

![diagram](/assets/images/HTCB/HTCB2.png)

### Step 2- Share the power supply 
Our first (top) breadboard already has the power supply connected to it. Joining the boards does **not** pass the power to the bottom one, so we connect the power rails with jumper wires. 
1. Connect one jumper wire from the **ground** rail of the top breadboard to the **ground** rail of the bottom breadboard. 
2. Connect the other jumper wire from the **HIGH supply (+5 V)** rail of the top breadboard to the **HIGH supply (+5 V)** rail of the bottom breadboard.

![diagram](/assets/images/HTCB/HTCB3.png)

Make sure ground goes to ground and HIGH goes to HIGH. If you cross them, your circuit will not work, and it can damage your components.

### Step 3- Test the connection
We can check that the power reached the bottom breadboard with a resistor and an LED. This is the same LED setup we used in the gate practicals. 
1. Connect one leg of the resistor to the HIGH supply rail of the **bottom** breadboard. 
2. Put the other leg of the resistor in any free column on the bottom breadboard. Holes in the same column are connected together. 
3. In that same column, place the **longer leg** of the LED. 
4. Connect the **shorter leg** of the LED to the ground rail of the bottom breadboard. If the LED lights up, the power supply is reaching the bottom breadboard, and your two breadboards are connected correctly.

![diagram](/assets/images/HTCB/HTCB5.png)

Lets take a cleaner look...

![diagram](/assets/images/HTCB/HTCB6.png)

This way you can get power supply between multiple breadboards!
