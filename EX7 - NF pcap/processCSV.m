
window = 60;
legends = {}
%%
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('low 2 (TL): %.2f MB per min',Mbpm)];
data1 = data;



%%
inVar = lowOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('low 1(TL): %.2f MB per min',Mbpm)];
data2 = data;

%%
inVar = lowNCOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('low(NC): %.2f MB per min',Mbpm)];
datalowNC = data;

%%
inVar = midOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('SD(TL): %.2f MB per min',Mbpm)];
dataSDTL = data;

%%
inVar = midNCOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('SD(NC): %.2f MB per min',Mbpm)];
dataSDNC = data;

%%
inVar = hdOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('HD(TL): %.2f MB per min',Mbpm)];
dataHDTL = data;


%%
inVar = hdNCOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('HD(NC): %.2f MB per min',Mbpm)];
dataHDNC = data;

%%
inVar = autoNCOut';
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
Mbpm = sum(inVar(2,:))*60/(maxTime*1000000);
legends = [legends,sprintf('Auto(NC): %.2f MB per min',Mbpm)];
dataAutoNC = data;





plot(data1)
hold on
plot(data2)
hold on
plot(datalowNC)
hold on
plot(dataSDTL)
hold on
plot(dataSDNC)
hold on
plot(dataHDTL)
hold on
plot(dataHDNC)
hold on
plot(dataAutoNC)
legend(legends);
hold off
