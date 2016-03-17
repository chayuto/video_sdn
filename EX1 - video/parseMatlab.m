
[Time,DesIP,DesPort,SrcIP,SrcPort,Len] = mLoadTrace('Netflix_trace',1, 37262);
%[Time,DesIP,DesPort,SrcIP,SrcPort,Len] = mLoadTrace('Youtube_trace',1, 48070);

dTime = zeros(length(Time),2);
iniTime = 0;
A = strsplit(Time{1},' ');
[H,M,S]=strread(A{2}, '%d%d%f', 'delimiter', ':');
seconds = S + M *60 + H*60*60;
iniTime = seconds;
dTime(1,:) = [0,Len(1)];
    
for i = 2:length(Time)
    A = strsplit(Time{i},' ');
    [H,M,S]=strread(A{2}, '%d%d%f', 'delimiter', ':');
    seconds = S + M *60 + H*60*60;
    rounded = round(seconds - iniTime,6);
    dTime(i,:)  = [rounded,Len(i)];
end





