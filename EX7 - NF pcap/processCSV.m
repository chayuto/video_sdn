
    FontSize = 15;
    legends = {};
    %%
    
    
% [data,timeIndex,Mbps] = processFlow(lowOut);
% legends = [legends,sprintf('low(TL): %.2f Mbps',Mbps)];
% plot(timeIndex,data)
% hold on

%%
[data,timeIndex,Mbps] = processFlow(lowNCOut);
legends = [legends,sprintf('low(NC): %.2f Mbps',Mbps)];
plot(timeIndex,data)
hold on

%%
% [data,timeIndex,Mbps] = processFlow(midOut);
% legends = [legends,sprintf('SD(TL): %.2f Mbps',Mbps)];
% plot(timeIndex,data)
% hold on

%%
[data,timeIndex,Mbps] = processFlow(midNCOut);
legends = [legends,sprintf('SD(NC): %.2f Mbps',Mbps)];
plot(timeIndex,data)
hold on

%%
% [data,timeIndex,Mbps] = processFlow(hdOut);
% legends = [legends,sprintf('HD(TL): %.2f Mbps',Mbps)];
% plot(timeIndex,data)
% hold on


%%
[data,timeIndex,Mbps] = processFlow(hdNCOut);
legends = [legends,sprintf('HD(NC): %.2f Mbps',Mbps)];
plot(timeIndex,data)

hold on

%%
[data,timeIndex,Mbps] = processFlow(autoNCOut);
legends = [legends,sprintf('Auto(TL): %.2f Mbps',Mbps)];
plot(timeIndex,data)
axis([0 300 0 15])
hold on


h_ylbl = ylabel('Mbps');
h_xlbl = xlabel('Time / Sec');
h_legend = legend(legends);
set(h_legend,'FontSize',FontSize);
set(h_ylbl,'FontSize',FontSize);
set(h_xlbl,'FontSize',FontSize);
hold off
