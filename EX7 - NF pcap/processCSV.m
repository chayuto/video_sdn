
window = 1;
legends = {};
res = 1;
startTime = 0;
FontSize = 15;

%%
inVar = lowOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)< (i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('low(TL): %.2f MB per min',Mbpm)];
data2 = data;
plot(timeIndex,data)
hold on

%%
inVar = lowNCOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>=i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('low(NC): %.2f MB per min',Mbpm)];
datalowNC = data;
plot(timeIndex,data)
hold on

%%
inVar = midOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('SD(TL): %.2f MB per min',Mbpm)];
dataSDTL = data;
plot(timeIndex,data)
hold on

%%
inVar = midNCOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('SD(NC): %.2f MB per min',Mbpm)];
dataSDNC = data;
plot(timeIndex,data)
hold on

%%
inVar = hdOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('HD(TL): %.2f MB per min',Mbpm)];
dataHDTL = data;
plot(timeIndex,data,'-x')
hold on


%%
inVar = hdNCOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('HD(NC): %.2f MB per min',Mbpm)];
dataHDNC = data;
plot(timeIndex,data,'-o')
hold on

%%
inVar = autoNCOut';
minTime =  min(inVar(1,:));
inVar(1,:) = inVar(1,:) - minTime;
maxTime = max(inVar(1,:));
maxTime = round(maxTime);


timeIndex = startTime:res:maxTime;
len  = length(timeIndex);
data = zeros(len,1);
counter = 1;
for i = timeIndex
    Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)<(i)));
    data(counter) = Bytes/1024000;
    counter = counter+1;
end
Mbpm = sum(inVar(2,:))*60/(maxTime*1024000);
legends = [legends,sprintf('Auto(NC): %.2f MB per min',Mbpm)];
plot(timeIndex,data,'-*')
hold on
dataAutoNC = data;


h_ylbl = ylabel('MB per mins');
h_xlbl = xlabel('Time / Sec');
h_legend = legend(legends);
set(h_legend,'FontSize',FontSize);
set(h_ylbl,'FontSize',FontSize);
set(h_xlbl,'FontSize',FontSize);
hold off
