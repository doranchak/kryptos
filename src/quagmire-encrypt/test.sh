make

echo Expected ciphertext: 
echo KRSLWMITJDVIABMRGQMTMLLIVIFUIXRHTNYONVRHHIIIRMCAOVEI
echo Actual ciphertext:
./encrypt test-encrypt.txt AUTOMOBILE HIGHWAY

echo Expected plaintext: 
echo THESAMEKEYEDALPHABETISUSEDFORPLAINANDCIPHERALPHABETS
echo Actual ciphertext:
./decrypt test-decrypt.txt AUTOMOBILE HIGHWAY
