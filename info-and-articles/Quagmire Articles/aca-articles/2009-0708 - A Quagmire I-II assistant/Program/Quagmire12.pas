program Quagmire12;	{ Windows version July 22, 2009. Does both }
{	QuagmireI and QuagmireII: ct = 1 or 2. When keyword is entered, }
{	entire alphabet tableau is constructed from letters present. April 26/09}
label
	13;
 const
	LetS = ['a'..'z','A'..'Z','-','='];	{ set of legal input chars }
	maxstack = 200;		{ size of save stack }
 type
  frecord = record		{ letter frequency }
    fr: integer;			{ denotes frequency of cipher letter in message }
    let: char;				{ denotes the cipher letter }
   end;
 type
  stackentry = record	{ what is saved on the stack: alphabets and solution }
    alphs: array[1..20] of string;	{ alphabets }
		sols: string;										{ solution }
   end;
 type
	stacktype = record	{ define stack used to save alphabets and solutions }
		top: 0..maxstack;	{ represents current depth of stack }
		entry: array[1..maxstack] of stackentry
	end;

 var
  str, str1, tip, outstr, tippat, tipv, sol, AtoZ, numstr: string;
	keyw, keyalph, str2: string[26];
  i, i1, j, jj, k, lt, tm, rem, nr, col, len, ct, nlet, lenk, kbest, shift: integer;
  alph: array[1..20] of string;
  totalphi, meanphi, bestmean, temp: real;
  colfreq: array[1..15, 1..26] of frecord;	{ for individual columns }
  tpat: array[1..50] of integer;		{ pattern words for tip dragging }
  vect: array[1..26, 1..26] of integer;
  Infile, Outfile: text;
  C,D: char;
  popflag, pushflag: boolean;
	S: stacktype;
  SC: set of char;

 function patstr (cstr: string): string;	{ operates on tip-length strings. }
 {	Only worry about same-column matches. }
  var
   i, j: integer;
   dstr: string;
 begin
		dstr := '';
		for i := 1 to lt - 1 do
			begin
				for j := i + 1 to lt do
					begin
						if (cstr[i] = cstr[j]) and ((j - i) mod k = 0) then
							begin
								tpat[i] := j - i;	{ gives integral distance }
								break;		{ found one for this i,don't wait for another }
							end
						else
							tpat[i] := 0;
					end;	{ of j loop}
			end;	{ of i loop }
		for i := 1 to lt - 1 do
			begin
				if tpat[i] > 9 then
					dstr := concat(dstr, chr(tpat[i] + 55))		{ letter }
				else
					dstr := concat(dstr, chr(tpat[i] + 48));	{ number }
			end;	{ of i loop }
  patstr := dstr;
 end;	{ of function patstr }

 function phi (j: integer): real;		{ calculates phi=IC for column j }
  var
   n, d: real;
   i: integer;
 begin
		n := 0;		{ numerator }
		d := 0;		{ denominator }
		for i := 1 to 26 do
			begin
				n := n + vect[j, i] * (vect[j, i] - 1);
				d := d + vect[j, i];
			end;
		phi := n / d / (d - 1);
 end;		{ of function phi }

 procedure FillVector (kk: integer);	{ vect[i,j] holds frequency for }
				{ each letter for each alphabet.  Used in phi }
  var
   i, j, z: integer;
 begin
		for i := 1 to 26 do		{ clear array }
			for j := 1 to 26 do
				vect[i, j] := 0;
		z := 0;								{ column index }
		for i := 1 to len do	{ go over every letter, assigning frequency count to a column }
			begin
				z := z + 1;					{ bump column number for each new letter }
				if z > kk then
					z := 1;						{ go back to first column }
				j := ord(str[i]) - 64;			{ get letter number }
				vect[z, j] := vect[z, j] + 1;	{ increment count for that letter in that column }
			end;
 end;	{ of procedure FillVector }

 procedure Push(x: stackentry; var S: stacktype);	{ push stackentry to stack }
 begin
		with S do
			if top = maxstack then
				begin
					writeln(' ERROR: Attempt to push an entry onto a full stack');
					pushflag := true;
				end
			else
				begin
					inc(top);
					entry[top] := x;		{ really means S.entry[S.top] := x }
				end;
 end;	{ of procedure Push }

 procedure Pop(var x: stackentry; var S: stacktype);	{ pop stackentry off stack }
 begin
		with S do
			begin
				if top = 0 then
					begin
						writeln(' ERROR: Attempt to pop an entry from an empty stack');
						popflag := true;
						exit
					end
				else
					begin
						x := entry[top];		{ really means x := S.entry[S.top] }
						dec(top);
					end;
			end;
 end;	{ of procedure Pop }

 procedure SaveState;
 var
	SE: stackentry;
 begin
		with SE do
			begin			{ load stackentry }
				alphs := alph;
				sols := sol;
			end;
		Push(SE,S);					{ push this stackentry SE onto stack S }
		if pushflag then		{ pushflag raised in push if stack is full }
			begin
				writeln(' Exiting program because stack is full!');
				halt;
			end;
		popflag := false;
 end;		{ of procedure SaveState }

 procedure RecallState;
 var
	SE: stackentry;
 begin
		Pop(SE,S);
		if popflag then			{ popflag raised in pop if stack is empty }
			begin
				writeln(' No more undos possible');
				write(chr(7));		{ beep }
				exit;
			end;
		pushflag := false;
		with SE do
			begin			{ retrieve stackentry }
				alph := alphs;
				sol := sols;
			end;
 end;		{ of procedure RecallState }
 
	procedure PlaceTipLet(n:integer);
	var
		i, j: integer;
	begin
	for i := n to n + lt - 1 do
		begin
			col := (i - 1) mod k + 1;		{ column index is also alphabet index }
			if ct = 2 then	{ Quagmire II }
				begin
					j := ord(tip[i - n + 1]) - 64;	{ get plaintext letter position, corrected JULY22/09 }
					alph[col][j] := str[i];			{ put cipher equivalent in correct alphabet }
				end
			else
				begin	{ Quagmire I }
					j := ord(str[i]) - 64;					{ get ciphertext letter position }
					alph[col][j] := tip[i - n + 1];	{ put tip equivalent in correct alphabet }
				end;
		end;	{ of i loop }
	end;	{ of procedure PlaceTipLet }
	
	procedure Consolidate;
	var
		i, j, i1, i2, i3:integer;
	begin
		for col := 1 to k do
			for i := 1 to 26 do
				begin
					j := ord(alph[col][i]) - 64;	{ get letters out of this alphabet }
					if j > 0 then					{ found one }
						for i1 := 1 to k do			{ go to other alphabets }
							if i1 <> col then
								for i2 := 1 to 26 do
									if char(j + 64) = alph[i1][i2] then
										for i3 := 1 to 26 do		{ move this alphabet to original alphabet if a letter }
											if alph[i1][i3] <> '.' then
												alph[col][(i - i2 + i3 + 25) mod 26 + 1] := alph[i1][i3];
				end;	{ have alphabets now }
	end;	{ of procedure Consolidate }

	procedure XferToSol;
	var
		i, j:integer;
	begin
		for i := 1 to len do
			sol[i] := '.';					{ fill sol with dots }
		for i := 1 to len do
			begin
				col := (i - 1) mod k + 1;		{ column index is also alphabet index }
				if ct = 2 then	{ Quagmire II }
					begin
						for j := 1 to 26 do
							if alph[col][j] = str[i] then
								begin
									sol[i] := char(j + 64);
									break;	{ exit j-loop once match is found }
								end
							else
								sol[i] := '.';
					end
				else
					begin	{ Quagmire I }
						j := ord(str[i]) - 64;			{ get ciphertext letter position }
						sol[i] := alph[col][j];
					end;
			end;	{ of i loop }
	end;	{ of procedure XferToSol }

procedure ClearAlph(k:integer);
var
	i, j:integer;
begin
	for i := 1 to k do
		alph[i] := '';
	for i := 1 to k do
		for j := 1 to 26 do
			alph[i] := concat(alph[i], '.');		{ blank alphabet strings }
end;	{ of procedure ClearAlph }

procedure Stop;
var
	i:integer;
begin
	for i := 1 to len do
		write(Outfile,sol[i]);
		close(Outfile);
		writeln(' Solution written to text file: ',outstr);	
		write(' Press <Enter>: ');
		readln;
		halt;
end;	{ procedure Stop }

	function ReadInteger(prompt: string; imin, imax: integer): integer;
	var		{ Checks for valid number entered; range must be between imin and imax }
		num, code: integer;
		NumString: string[20];
		flag: boolean;
	begin
		repeat
			flag := true;		{ assume valid number }
			write(prompt);
			readln(NumString);
			if NumString = '-1' then
				stop;
			Val(NumString, num, code);	{ get value }
			if (code <> 0) or (num < imin) or (num > imax) then
				begin
					flag := false;		{ invalid number }
					write(chr(7));		{ beep }
				end;
		until (flag) and (code = 0);
		ReadInteger := num;
	end;	{ of function ReadInteger }

	function ReadLetter(prompt: string): char;
	var		{ Checks for valid letter entered; must be in set LetS }
		LetString: string[20];
		flag: boolean;
	begin
		repeat
			flag := true;		{ assume valid letter }
			write(prompt);
			readln(LetString);
			if LetString = '-1' then
				stop;
			if not(LetString[1] in LetS) then
				begin
					flag := false;		{ invalid letter }
					write(chr(7));
				end;
		until flag;
		ReadLetter := LetString[1];
	end;	{ of function ReadLetter }

	function ReadKey(prompt: string): string;
	var		{ Checks for valid letters entered; must be in set LetS }
		LetString: string;
		flag: boolean;
	begin
		repeat
			flag := true;		{ assume valid string }
			write(prompt);
			readln(LetString);
			if LetString = '-1' then
				stop;
			for i := 1 to length(LetString) do
				if not(LetString[i] in LetS) then
					begin
						flag := false;		{ invalid letter }
						write(chr(7));
					end
				else
					LetString[i] := upcase(LetString[i]);	{ convert to upper case }
		until flag;
		ReadKey := LetString;
	end;	{ of function ReadKey }

begin
	ct := ReadInteger( ' ENTER "1" for QUAGMIRE I or "2" for QUAGMIRE II: ',1,2);
	if ct = 2 then
		writeln('      QUAGMIRE II ASSISTANT')
	else
		writeln('      QUAGMIRE I ASSISTANT');
	write(' ENTER FILE NAME ("-1" TO QUIT): ');
	readln(str1);
	if str1 = '-1' then
		halt;
	assign(Infile, str1);					{ open Infile with title str1 }
	{$I-}
	reset(Infile);			{ open Infile with title str1 }
	{$I+}
	if IOResult <> 0 then
		begin
			writeln(' Error opening file ',str1);
			write(' Press <Enter>: ');
			readln;
			halt;
		end;
 readln(Infile, str);			{ read in puzzle into str}
 insert('sol',str1,pos('.txt',str1));	{ insert 'sol' before '.txt' in str1 }
 outstr := str1;
 assign(Outfile, outstr);				
 rewrite(Outfile);						{ open output file }
 len := length(str);			{ length of string }
 sol := str;							{ set up sol as string with same length as input }
 for i := 1 to len do
  sol[i] := '.';					{ fill sol with dots }
 readln(Infile, tip);			{ read in tip }
 tipv := tip;							{ tip-length string }
 lt := length(tip);
 writeln(' Length=', len : 3, ' Tip=', tip, '  Tip length=', lt : 3);
 writeln;
 AtoZ := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
 numstr := '123456789ABCDEFGHIJK';

{		Initialize frequency records and column array }

	pushflag := false;					{ error on push flag }
	popflag := false;						{ error on pop flag }
	S.top := 0;									{ initialize saving stack }

{		Using keyword length k, calculate IC for each column generated, and }
{		get the average for that key length  }

 bestmean := 0;					{ initialize bestmean }
 for k := 3 to 16 do		{ k = keyword length }
  begin									
   FillVector(k);
   totalphi := 0;
   for col := 1 to k do				{ get average phi for this k }
    begin
     temp := phi(col);
     totalphi := totalphi + temp;
    end;
   meanphi := totalphi / k;			{ average phi }
   writeln(' k =', k : 3, '  meanphi ', meanphi : 8 : 4);
   if meanphi > bestmean then
    begin
     bestmean := meanphi;			{ best so far }
     kbest := k;
    end;
  end;		{ of k loop }
 writeln(' Bestmean =', bestmean : 8 : 4, '  kbest =', kbest : 3);
 k := ReadInteger(' ENTER THE KEYWORD LENGTH ("-1" to QUIT): ',3,16);
 if k = -1 then
  halt;
 nr := len div k;				{ number of rows if length of cipher is divisible by period }
 rem := len mod k;			{ number of letters in non-full row }
 ClearAlph(k);
 
{		Initialize column frequency arrays }

 for i := 1 to 13 do
  for j := 1 to 26 do
   begin
    colfreq[i][j].let := char(j + 64);
    colfreq[i][j].fr := 0;
   end;

{		Calculate individual column frequency arrays once period is chosen }

 for i := 1 to len do
  begin
   col := (i - 1) mod k + 1;			{ column array, same as alphabet number }
   j := ord(str[i]) - 64;					{ get index into freq of this cipher character }
   colfreq[col][j].fr := colfreq[col][j].fr + 1;		{ increment frequency count }
  end;

{		Set up pattern word for tip.  Only note duplicates in the same column }

 tippat := patstr(tip);

{		Drag tip through cipher.  Get tip-length pieces of cipher in tipv, make pattern word cpat[i], compare with tpat[i] }

 tm := 0;													{ keep track of multiple tip matches }
 for i := 1 to len - lt + 1 do
	begin														{ start comparison }
		tipv := copy(str, i, lt);			{ grab tip-length piece }
		if patstr(tipv) = tippat then	{ tip match here }
			begin
				ClearAlph(k);			{ start with clear alphabets }
				PlaceTipLet(i);		{ i is tip position }
				Consolidate;			{ consolidate alphabets }
				XferToSol;				{ get solution }
				if pos(tip,sol) > 0 then	{ if tip survives }
					begin
						writeln(' Tip match at position ', i : 4);
						tm := tm + 1;							{ increment tip match counter }
						jj := i;									{ save position }
				end;
			end;
	end;	{ of i-loop comparison }
	writeln(' Number of tip matches=', tm : 2);
	writeln;
	if tm > 1 then
		begin
			jj := ReadInteger(' ENTER TIP PLACEMENT POSITION ("-1" to QUIT): ',-1,len-lt+1);
			if jj = -1 then
				halt;
		end;	{ of multiple tip positions }

{		Place tip letters in alphabets }

 writeln(' Tip placement at ', jj : 3);
 ClearAlph(k);
 PlaceTipLet(jj);		{ jj is tip position }
 
{		Consolidate alphabets: ALL CT ALPHABETS ARE IDENTICAL BUT SHIFTED IN QUAGII }

 Consolidate;
 
{		Transfer letters from alphabets to sol }

 XferToSol;	{ get sol }

{		Main loop - come here after putting in guess letters }

 repeat
	Consolidate;
	XferToSol;

{		Write out cipher and solution in columns, and tableau of alphabets and frequencies }

	nlet := 0;	{ calculate number of letters in cipher alphabet tableau }
	for i := 1 to k do
		for j := 1 to 26 do
			if ord(alph[i][j]) > 64 then
				nlet := nlet + 1;
	write('     ');
	write(copy(numstr,1,k),'    ',copy(numstr,1,k),'    # Letters in tableau: ',nlet:3);
	for i := 1 to 6 do
		write('  ');
	writeln(' CIPHER FREQUENCIES');
  for i := 1 to nr do
   begin
    write(i : 3, '  ');
    for j := 1 to k do
     write(str[j + k * (i - 1)]);
    write('    ');
    for j := 1 to k do
     write(sol[j + k * (i - 1)]);
    if i = 1 then
			if ct = 2 then	{ QUAGMIRE II }
				write('    pt 0 ', AtoZ,'   ',AtoZ)
			else						{ QUAGMIRE I }
				write('    ct 0 ', AtoZ,'   ',AtoZ);			
    i1 := i - 1;
    if ((i1 > 0) and (i1 < k + 1)) then
			begin
				if ct = 2 then	{ QUAGMIRE II }
					write('    ct ', i1 : 1, ' ', alph[i1],'   ')
				else						{ QUAGMIRE I }
					write('    pt ', i1 : 1, ' ', alph[i1],'   ');
				for j := 1 to 26 do
					write(colfreq[i1][j].fr : 1);
			end;
    writeln;
   end;
  if rem > 0 then
   begin
    write(nr + 1 : 3, '  ');
    for i := len - rem + 1 to len do
     write(str[i]);
    for i := 1 to k - rem + 4 do
     write(' ');
    for i := len - rem + 1 to len do
     write(sol[i]);
   end;
  writeln;
  if len < 81 then
   writeln(sol)
  else if len > 80 then
   begin
    writeln(' ',copy(sol, 1, 80));		{ first 80 char of sol }
    writeln(' ',copy(sol, 81, 80));		{ second 80 char of sol }
    writeln(' ',copy(sol, 161, 80));	{ third 80 char of sol }
   end;

{		Enter guesses for letters in alphabets }

  col := ReadInteger(' ENTER THE ALPHABET NUMBER FOR A GUESS REPLACEMENT ("-1" to QUIT,"0" to UNDO): ',0,k);
	if col = 0 then
		begin
			RecallState;		
			goto 13;
		end;
  if col = -1 then
   stop;
	SaveState;	{ if you get here, save current alphabet before modifying with new input }
  C := ReadLetter(' ENTER THE PLAINTEXT LETTER TO BE ADDED ("-1" to QUIT,"=" to ENTER KEYWORD): ');
  if C = '-' then
   stop;
	if C = '=' then
		begin
			keyw := ReadKey(' ENTER KEYWORD: ');
			keyw := upCase(keyw);	{ upper case };
			SC := [];					{ start with empty set }
			lenk := length(keyw);
			keyalph := '';			{ start with blank }
			for i := 1 to lenk do
				if not (keyw[i] in SC) then
					begin
						SC := SC + [keyw[i]];
						keyalph := concat(keyalph, keyw[i]);
					end;
			for C := 'A' to 'Z' do
				if not (C in SC) then
					keyalph := concat(keyalph, C);	{ now have keyed alphabet }
			str2 := keyalph;

{			Look in first alphabet for a letter, match with keyalph position, and shift }

			for j := 1 to 26 do
				begin
					if ord(alph[1][j]) > 64 then		{ found a letter at position j in plaintext alph }
						begin
							shift :=  pos(chr(j + 64),AtoZ) - pos(alph[1][j],keyalph);	{ where is letter in keyalph? }
							for i := 1 to 26 do
								str2[i] := keyalph[(i - shift + 25) mod 26 + 1];
							alph[1] := str2;
							break;	{ exit from j loop }
						end;
				end;	{ of j loop }
			goto 13;	{ exit, construct solution }
		end;
	C := upcase(C);
  D := ReadLetter(' ENTER THE ASSOCIATED CIPHERTEXT LETTER ("-1" to QUIT): ');
  if D = '-' then
   stop;
	D := upcase(D);
	if ct = 2 then
		alph[col][ord(C) - 64] := D		{ QUAGMIRE II }
	else
		alph[col][ord(D) - 64] := C;	{ QUAGMIRE I }
13:
 until 1 = 0;
end.