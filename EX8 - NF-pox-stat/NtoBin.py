def GetArray(N):
	Array = [0]
	while len(Array)<= N+1:	
		new_Array = [x+1 for x in Array]
		#print new_Array
		Array = Array + new_Array
	return Array[:N+1]

def GetArray2(N):
	Array = [0];
	c1 = 1;
	for i in range(1,N+1):
		if i >= c1*2:
			c1 = c1*2;
		Array.append(Array[i-c1]+1)

	return Array 

print GetArray2 (31)
print GetArray (31)


