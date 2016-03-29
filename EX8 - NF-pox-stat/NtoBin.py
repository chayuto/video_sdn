def GetArray(N):
	Array = [0]
	while len(Array)<= N+1:	
		new_Array = [x+1 for x in Array]
		#print new_Array
		Array = Array + new_Array
	return Array[:N+1]


print GetArray (15)


