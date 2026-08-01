# SIPFA on Lilliput-TBC-II-128 and SCENERY-64/80

Four SIPFA scenarios were implemented on both ciphers:

1. **Known fault with detection**  
   The final-round key was fully recovered on both algorithms.

2. **Unknown fault with detection**  
   On Lilliput, the fault value and final-round tweakey were recovered.  
   On SCENERY, the faulty S-box, the fault value, and 18 of 20 active key bits were recovered.

3. **Known fault with infection**  
   The final-round key was fully recovered on both algorithms using minimum-frequency analysis.

4. **Unknown fault with infection**  
   On Lilliput, the fault value and final-round tweakey were recovered using statistical ranking.  
   On SCENERY, the fault value and 18 of 20 active key bits were recovered, while four structurally equivalent candidates remained.

For Lilliput, the complete 128-bit master key was also recovered using two round tweakeys.  
For SCENERY, the complete 32-bit final-round key was recovered in the known-fault scenarios.
