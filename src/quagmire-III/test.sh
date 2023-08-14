make


echo -------------------------------------------------------------------------------------------
echo Example from https://www.cryptogram.org/downloads/aca.info/ciphers/QuagmireIII.pdf
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo KRSLWMITJDVIABMRGQMTMLLIVIFUIXRHTNYONVRHHIIIRMCAOVEI
echo Actual ciphertext:
./encrypt test-encrypt.txt AUTOMOBILE HIGHWAY

echo Expected plaintext: 
echo THESAMEKEYEDALPHABETISUSEDFORPLAINANDCIPHERALPHABETS
echo Actual plaintext:
./decrypt test-decrypt.txt AUTOMOBILE HIGHWAY

echo
echo -------------------------------------------------------------------------------------------
echo K1
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD
echo Actual ciphertext:
./encrypt test-K1-pt.txt KRYPTOS PALIMPSEST

echo Expected plaintext: 
echo BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION
echo Actual plaintext:
./decrypt ../../ciphers/kryptos/K1.txt KRYPTOS PALIMPSEST

echo
echo -------------------------------------------------------------------------------------------
echo K2
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG
echo Actual ciphertext:
./encrypt test-K2-pt.txt KRYPTOS ABSCISSA

echo Expected plaintext: 
echo ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS
echo Actual ciphertext:
./decrypt ../../ciphers/kryptos/K2.txt KRYPTOS ABSCISSA
