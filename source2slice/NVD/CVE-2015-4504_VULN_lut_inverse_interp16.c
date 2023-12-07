uint16_fract_t lut_inverse_interp16(uint16_t Value, uint16_t LutTable[], int length)
{
        int l = 1;
        int r = 0x10000;
        int x = 0, res;       // 'int' Give spacing for negative values
        int NumZeroes, NumPoles;
        int cell0, cell1;
        double val2;
        double y0, y1, x0, x1;
        double a, b, f;

        // July/27 2001 - Expanded to handle degenerated curves with an arbitrary
        // number of elements containing 0 at the begining of the table (Zeroes)
        // and another arbitrary number of poles (FFFFh) at the end.
        // First the zero and pole extents are computed, then value is compared.

        NumZeroes = 0;
        while (LutTable[NumZeroes] == 0 && NumZeroes < length-1)
                        NumZeroes++;

        // There are no zeros at the beginning and we are trying to find a zero, so
        // return anything. It seems zero would be the less destructive choice
	/* I'm not sure that this makes sense, but oh well... */
        if (NumZeroes == 0 && Value == 0)
            return 0;

        NumPoles = 0;
        while (LutTable[length-1- NumPoles] == 0xFFFF && NumPoles < length-1)
                        NumPoles++;

        // Does the curve belong to this case?
        if (NumZeroes > 1 || NumPoles > 1)
        {               
                int a, b;

                // Identify if value fall downto 0 or FFFF zone             
                if (Value == 0) return 0;
               // if (Value == 0xFFFF) return 0xFFFF;

                // else restrict to valid zone

                a = ((NumZeroes-1) * 0xFFFF) / (length-1);               
                b = ((length-1 - NumPoles) * 0xFFFF) / (length-1);
                                                                
                l = a - 1;
                r = b + 1;
        }


        // Seems not a degenerated case... apply binary search

        while (r > l) {

                x = (l + r) / 2;

		res = (int) lut_interp_linear16((uint16_fract_t) (x-1), LutTable, length);

                if (res == Value) {

                    // Found exact match. 
                    
                    return (uint16_fract_t) (x - 1);
                }

                if (res > Value) r = x - 1;
                else l = x + 1;
        }

        // Not found, should we interpolate?

                
        // Get surrounding nodes
        
        val2 = (length-1) * ((double) (x - 1) / 65535.0);

        cell0 = (int) floor(val2);
        cell1 = (int) ceil(val2);
           
        if (cell0 == cell1) return (uint16_fract_t) x;

        y0 = LutTable[cell0] ;
        x0 = (65535.0 * cell0) / (length-1); 

        y1 = LutTable[cell1] ;
        x1 = (65535.0 * cell1) / (length-1);

        a = (y1 - y0) / (x1 - x0);
        b = y0 - a * x0;

        if (fabs(a) < 0.01) return (uint16_fract_t) x;

        f = ((Value - b) / a);

        if (f < 0.0) return (uint16_fract_t) 0;
        if (f >= 65535.0) return (uint16_fract_t) 0xFFFF;

        return (uint16_fract_t) floor(f + 0.5);                        

}
