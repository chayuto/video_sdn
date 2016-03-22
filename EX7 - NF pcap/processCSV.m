
window = 60;

inVar = low2Out';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


maxIndex = maxTime-window;
timeIndex = 0:1:maxIndex;
len  = length(timeIndex);
data = zeros(maxIndex,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i & inVar(1,:)<(i+window)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000)
0:maxIndex