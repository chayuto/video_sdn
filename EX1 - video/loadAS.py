servListRAW = tuple(open('./Netflix_AS2906', 'r'))
servList = []
for i in servListRAW:
  strIn = i.strip()
  parts = strIn.split("/")
  print parts[0] + " - " + parts[1]
  #servList.append(i.strip()) #remove \n character at the end of the line
