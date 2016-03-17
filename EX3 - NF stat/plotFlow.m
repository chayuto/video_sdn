timeMax = max(time);


Flows = unique(cookie);
Flows = Flows(Flows>=1000);
flowCount = length(Flows);

data = zeros(flowCount,timeMax);
for i = 1:length(time)
    if cookie(i)>=1000
        data(Flows==cookie(i),time(i))= byte_count(i)*8;
    end
end

figure(1)
labels = [];
for i = 1:flowCount
    semilogy(1:timeMax,data(i,1:timeMax),'-o')
    labels = [labels;int2str(Flows(i))];
    hold on
end
legend(labels);
ylabel('mbps');
xlabel('Time/Sec');
title('Flowstat of netflix ipPrefixes')
hold off


