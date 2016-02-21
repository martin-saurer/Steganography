NB. *****************************************************************************
NB. File:        stegano.ijs
NB. Author:      Martin Saurer, 18.02.2012
NB. Description: Steganography example.
NB.              Hide a message in a bitmap image.
NB.
NB. License:     GPL Version 3 (see gpl3.txt)
NB.
NB.              M. Saurer, 24.03.2014
NB.              More compact version.
NB. *****************************************************************************

NB. Required scripts
require 'graphics/bmp'

NB. *****************************************************************************
NB. Utility verbs
NB. *****************************************************************************

NB. Convert string to bit-stream
NB. Usage: <length> str2bit '<string>'
NB. str2bit =: 4 : ',/_1}.#:((#y),(a.i.y),((0>.((x-1)-#y))$255?255),128)'
str2bit =: 4 : ',/_1}.#:((int2rgb #y),(a.i.y),((0>.((x-1)-#y))$255?255),128)'

NB. Convert bit-stream to string
NB. Usage: bit2str <bit-stream>
NB. bit2str =: 3 : '(#.(1+i.#.{.(((8%~#y),8)$y)){(((8%~#y),8)$y)){a.'
bit2str =: 3 : '(#.(3+i. rgb2int #.3{.(((8%~#y),8)$y)){(((8%~#y),8)$y)){a.'

NB. Convert rgb-image-array to integer-image-array
NB. Usage: rgb2int <integer-image-array>
rgb2int =: 3 : '<.(((|:0{|:y)*2^16)+((|:1{|:y)*2^8)+(|:2{|:y))'

NB. Convert integer-image-array to rgb-image-array
NB. Usage: int2rgb <integer-image-array>
int2rgb =: 3 : '|:>(|:(<.256|(<.(<.y%256)%256)));(|:(<.256|(<.y%256)));(|:(<.256|y))'

NB. Convert integer array to string
int2str =: 3 : 'y { a.'

NB. Convert string to integer array
str2int =: 3 : 'a. i. y'

NB. Bitwise XOR
xor     =: 22 b.

NB. *****************************************************************************
NB. Arc4 algorithm (based on Kym Farnik's work)
NB. *****************************************************************************

NB. x = Key to use for encrypting and decrypting
NB. y = Plain Text or Encypted Text
NB.
NB. x can also be an integer array with integers >= 0 and <= 255 with a maximum
NB. length of 256 elements
crypt =: 4 : 0
   ky =. 256 $ str2int ^: ((32{a.)=({.0$x)) x    NB. Key  in x as integer array
   tx =. str2int ^: ((32{a.)=({.0$y)) y          NB. Text in y as integer array
   sv =. i. 256                                  NB. State Vector
   ii =. jj =. 0                                 NB. Set ii,jj to zero
   while. ii < 256 do.                           NB. Setup state vector
      jj =. 256 | jj + (ii{sv) + ii{ky           NB. jj = (jj+state[ii]+key[ii]) % 256
      sv =. ((ii,jj){sv) (jj,ii)}sv              NB. Swap state [ii] and [jj]
      ii =. >: ii                                NB. Increment ii
   end.
   ii =. jj =. kk =. 0                           NB. Set ii,jj,kk to zero
   while. kk < #tx do.                           NB. Traverse string
      ii =. 256 | >: ii                          NB. Increment i mod 256
      jj =. 256 | jj + ii{sv                     NB. Next jj (jj = jj+state[ii]) % 256)
      sw =. (ii,jj){sv                           NB. Get states to swap
      sv =. sw (jj,ii)}sv                        NB. Swap state [ii] and [jj]
      tx =. (((256|+/sw){sv) xor kk{tx) kk}tx    NB. k XOR string element[n]
      kk =. >: kk                                NB. Increment n
   end.
   int2str tx                                    NB. tx contains encrypted integer array
)

NB. Some experiments
NB. isstr =: 3 : '(32{a.)=({.0$y)'
NB. toarr =: 3 : 's2i ^: isstr y'
NB. mo256 =: 3 : '(>0{y);(256|(>1{y)+((>0{y){(>2{y))+((>0{y){(>3{y)));(>2{y);(>3{y)'
NB. swapv =: 3 : '(>:>0{y);(>1{y);((((>0{y),(>1{y)){(>2{y)) ((>1{y),(>0{y))}(>2{y));(>3{y)'
NB. statv =: 3 : 'swapv mo256 y'
NB. indxi =: 3 : '(<256|>:>0{y) (0,0)}y'
NB. indxj =: 3 : '(<256|(>1{y)+((>0{y){(>3{y))) (1,1)}y'
NB. swapt =: 3 : '(((>0{y),(>1{y)){(>3{y)) ((>1{y),(>0{y))}(>3{y)'
NB. crypv =: 3 : ''
NB. crypt2 =: 4 : 0
NB.    sv =: >2{{: statv ^: (i.257) (0;0;(i.256);(256 $ toarr x))
NB.    tx =: swapt indxj indxi (0;0;0;sv;toarr y)
NB. )

NB. *****************************************************************************
NB. Steganography
NB. *****************************************************************************

NB. Hides a message in a bitmap-image
NB. Usage: '<Message-to-hide>';<Password> hidemsg '<Bitmap-image-file>'
hidemsg =: 4 : 0
   tex =. >0{x                                      NB. Extract 1st x-arg: message
   pwd =. >1{x                                      NB. Extract 2nd x-arg: password
   bmf =. jpath y                                   NB. Full path to bitmap file in y
   stf =. (_4}.bmf),'_steg',(_4{.bmf)               NB. Build new file name
   bmp =. readbmp bmf                               NB. Read original bitmap file
   dim =. $bmp                                      NB. Get bitmap dimensions
   msg =. (*/dim)$(*/dim) str2bit (pwd crypt tex)   NB. Encrypt text, make bit stream
   rgb =. int2rgb bmp                               NB. Convert integers to RGB triples
   rpl =. |:0{|:rgb                                 NB. Extract red bit plane
   gpl =. |:1{|:rgb                                 NB. Extract green bit plane
   bpl =. ,/|:2{|:rgb                               NB. Extract blue bit plane
   bpl =. dim $ ((bpl - 2|bpl) + msg)               NB. Embed encrypted text
   bmp =. rgb2int |:>(|:rpl);(|:gpl);(|:bpl)        NB. Create new bitmap image
   bmp writebmp stf                                 NB. Write new bitmap file
)

NB. Hides a text file in a bitmap-image
NB. Usage: '<file-to-hide>';<Password> hidemsg '<Bitmap-image-file>'
hidetxt =: 4 : 0
   tex =. fread jpath >0{x                                 NB. Extract 1st x-arg: text file
   pwd =. >1{x                                             NB. Extract 2nd x-arg: password
   bmf =. jpath y                                          NB. Full path to bitmap file in y
   stf =. (_4}.bmf),'_steg',(_4{.bmf)                      NB. Build new file name
   bmp =. readbmp bmf                                      NB. Read original bitmap file
   dim =. $bmp                                             NB. Get bitmap dimensions
   msg =. (<.(((*/dim,3)-16)%8)) str2bit (pwd crypt tex)   NB. Encrypt text, make bit stream
   rgb =. int2rgb bmp                                      NB. Convert integers to RGB triples
   xpl =. (,/|:0{|:rgb),(,/|:1{|:rgb),(,/|:2{|:rgb)        NB. Concatenate all bit planes
   xpl =. (xpl - 2|xpl) + msg                              NB. Embed encrypted text
   xpl =. (3,dim) $ xpl                                    NB. Reshape xpl to rgb
   bmp =. rgb2int |:>(|:0{xpl);(|:1{xpl);(|:2{xpl)         NB. Create new bitmap image
   bmp writebmp stf                                        NB. Write new bitmap file
)

NB. Extract hidden message from bitmap-image
NB. Usage: <Password> showmsg '<Bitmap-image-file>'
showmsg =: 4 : 0
   pwd =. x                                         NB. Password in x-arg
   bmp =. readbmp jpath y                           NB. Bitmap file in y-arg
   rgb =. int2rgb bmp                               NB. Convert integers to RGB triples
   bpl =. 2|,/|:2{|:rgb                             NB. Extract blue bit plane (MOD 2)
   msg =. bit2str bpl                               NB. Convert bits back to string
   tex =. pwd crypt msg                             NB. Decrypt and return plain text
)

NB. Extract hidden text file from bitmap-image
NB. Usage: <Password> showmsg '<Bitmap-image-file>'
showtxt =: 4 : 0
   pwd =: x                                           NB. Password in x-arg
   bmp =. readbmp jpath y                             NB. Bitmap file in y-arg
   rgb =. int2rgb bmp                                 NB. Convert integers to RGB triples
   xpl =. (,/|:0{|:rgb),(,/|:1{|:rgb),(,/|:2{|:rgb)   NB. Concatenate all bit planes
   xpl =. 2|xpl                                       NB. Modulo 2
   msg =. bit2str xpl                                 NB. Convert bits back to string
   tex =. pwd crypt msg                               NB. Decrypt
   tex fwrite (jpath y),'.txt'                        NB. Write text file
)

NB. GUI definition
steg_win =: 0 : 0
   pc steg;
   pn Steganography;

   bin v;
   bin g;

   grid colwidth 0 180;

   grid cell 0 0; cc lab1 static right;    cn Input Bitmap-Image: ;
   grid cell 0 1; cc tex1 edit   readonly;
   grid cell 0 2; cc but1 button;          cn ...;
   grid cell 1 0; cc lab2 static right;    cn Output Bitmap-Image: ;
   grid cell 1 1; cc tex2 edit   readonly;
   grid cell 1 2; cc but2 button;          cn ...;
   grid cell 2 0; cc lab3 static right;    cn Password: ;
   grid cell 2 1; cc tex3 edit;
   grid cell 3 0; cc lab4 static right;    cn Text to hide: ;
   grid cell 3 1; cc tex4 edit;

   bin z;
   bin g;

   grid cell 0 0;                cc but3 button; cn Hide Text;
   grid cell 1 0; minwh 480 320; cc img1 image;
   grid cell 0 1;                cc but4 button; cn Show Text;
   grid cell 1 1; minwh 480 320; cc img2 image;
)

NB. GUI initialization
steg_run =: 3 : 0
   wd 'reset'
   wd steg_win
   wd 'pcenter'
   wd 'pshow'
)

NB. GUI termination
steg_close =: 3 : 0
   wd 'pclose'
)

NB. Select original bitmap
steg_but1_button =: 3 : 0
   ifn =. wd 'mb open1 "Select Bitmap-Image" "" "Bitmap (*.bmp)"'
   ifn =. >0{(LF splitstring ifn)
   if. 0 < #ifn do.
      wd 'set tex1 text ',ifn
      ofn =. (_4}.ifn),'_steg',(_4{.ifn)
      wd 'set tex2 text ',ofn
      wd 'set img1 image ',ifn
   end.
)

NB. Select bitmap with hidden text
steg_but2_button =: 3 : 0
   ofn =. wd 'mb open1 "Select Bitmap-Image" "" "Bitmap (*.bmp)"'
   ofn =. >0{(LF splitstring ofn)
   if. 0 < #ofn do.
      wd 'set tex2 text ',ofn
      wd 'set img2 image ',ofn
   end.
)

NB. Hide text
steg_but3_button =: 3 : 0
   ifn =. getval 'tex1'
   ofn =. getval 'tex2'
   pwd =. getval 'tex3'
   tex =. getval 'tex4'
   (tex;pwd) hidemsg ifn
   wd 'set img2 image ',ofn
)

NB. Show text
steg_but4_button =: 3 : 0
   ofn =. getval 'tex2'
   pwd =. getval 'tex3'
   tex =. pwd showmsg ofn
   wd 'set tex4 text ',tex
)

NB. Get value from child control (GUI widget/element)
getval =: 3 : 0
   fd =. wd 'qd'
   >(((<y) E. 0{|:fd) i. 1) { (1{|:fd)
)

NB. Run GUI when file is loaded
NB. Comment out, if you want to use this file as a library
steg_run''

NB. *****************************************************************************
NB. EOF
NB. *****************************************************************************
