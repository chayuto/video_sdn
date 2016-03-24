function [EMAdata,timeIndex,Mbps] = processFlow(inVar)

    window = 1;
    res = 1;
    startTime = 0;
    alpha = 0.1;
    %%
    inVar = inVar';
    minTime =  min(inVar(1,:));
    inVar(1,:) = inVar(1,:) - minTime;
    maxTime = max(inVar(1,:));
    maxTime = round(maxTime);
    timeIndex = startTime:res:maxTime;
    len  = length(timeIndex);
    data = zeros(len,1);
    EMAdata = zeros(len,1);
    counter = 1;
    for i = timeIndex
        Bytes = sum(inVar(2,inVar(1,:)>i-window & inVar(1,:)< (i)));
        data(counter) = Bytes * 8 /1024000;
        counter = counter+1;
    end
    previous = 0;
    for i = 1:length(data)
        previous = (alpha*data(i)) + (1-alpha)*previous;
        EMAdata(i) = previous;
    end
    Mbps = sum(inVar(2,inVar(1,:)>50) * 8 /((maxTime-50)*1024000)) ;
end