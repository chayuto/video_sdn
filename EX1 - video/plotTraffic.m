
res = 1;
max = dTime(end,1);
count = zeros(round(max/res)+1,1);
for i = 1:length(Time)
    index = round(dTime(i)/res)+1;
    count(index) = count(index) + Len(i);
    
end

mbps = count*8/(res*1000000) ;

timeindex  = linspace(0,max,length(mbps));
plot(timeindex, mbps);
 ylabel('Mbps')
 xlabel('Time/Sec')
