//      Copyright 2013 phra <phra[at]r0x>
//
//      This program is free software; you can redistribute it and/or modify
//      it under the terms of the GNU General Public License as published by
//      the Free Software Foundation; either version 2 of the License, or
//      (at your option) any later version.
//
//      This program is distributed in the hope that it will be useful,
//      but WITHOUT ANY WARRANTY; without even the implied warranty of
//      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//      GNU General Public License for more details.
//
//      You should have received a copy of the GNU General Public License
//      along with this program; if not, write to the Free Software
//      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//      MA 02110-1301, USA.
//



/**
 * strreverse(puntatore a char, puntatore a char): rovescia una stringa
 * \param begin inizio stringa
 * \param end fine stringa
 */
void strreverse(char* begin, char* end) {

        char aux;
        while(end>begin)
                aux=*end, *end--=*begin, *begin++=aux;

}

/**
 * itoa(valore, puntatore della stringa, base in cui convertire) : converte un intero in una stringa nella base specificata
 * \param value intero da convertire
 * \param str indirizzo dove scrivere la stringa
 * \param base base in cui convertire l'intero
 */
void itoa(int value, char* str, int base) {

        static char num[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        char* wstr=str;
        int sign;

        // Validate base
        if (base<2 || base>35){ *wstr='\0'; return; }

        // Take care of sign
        if ((sign=value) < 0) value = -value;

        // Conversion. Number is reversed.
        do *wstr++ = num[value%base]; while(value/=base);
        if(sign<0) *wstr++='-';
        *wstr='\0';

        // Reverse string
        strreverse(str,wstr-1);
}

/**
 * escapenewline(puntatore della stringa, lunghezza della stringa) : elimina il newline
 * \param str indirizzo dove scrivere la stringa
 * \param len lunghezza della stringa senza '\0'
 */
void escapenewline(char* str, unsigned int len) {
    if (str[len-1] == '\n')
        str[len-1] = '\0';
}
