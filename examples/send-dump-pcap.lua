local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local stats	 = require "stats"
local log    = require "log"
local ts      = require "timestamping"
local hist    = require "histogram"
local limiter = require "software-ratecontrol"
local pcap = require "pcap"

local PKT_SIZE	= 60
local ETH_DST	= "11:12:13:14:15:16"

function master(txPort, rate, rc, rxPort)
	if not txPort or not rate or not rc or not rxPort then
		return print("usage: txPort rate hw|sw|moongen rxPort")
	end

	rate = rate
	threads = 1
	pattern = "cbr"
	--local rxDev = device.config{port = rxPort, rxQueues = 2, rssQueues = 2, rssBaseQueue=0, dropEnable = false, rxDescs=1024}
	local rxDev = device.config{port = rxPort, rxQueues = 2, dropEnable = false, rxDescs=1024}
	local txDev = device.config{port = txPort, disableOffloads = rc ~= "moongen"}

	device.waitForLinks()
	stats.startStatsTask{txDevices = {txDev}, rxDevices = {rxDev}}

	local rateLimiter
	if rc == "sw" then
		rateLimiter = limiter:new(txDev:getTxQueue(0), pattern, 1 / rate * 1000)
	end
	mg.startTask("loadSlave", txDev:getTxQueue(0), txDev, rate, rc, pattern, rateLimiter, 1, threads)
	
	mg.startTask("dumpSlave", rxDev:getRxQueue(0), 1)
	mg.startTask("dumpSlave", rxDev:getRxQueue(1), 2)
	
	mg.waitForTasks()
end

function loadSlave(queue, txDev, rate, rc, pattern, rateLimiter, threadId, numThreads)
	local mem = memory.createMemPool(4096, function(buf)
		buf:getUdpPacket():fill{
			ethSrc = txDev,
			ethDst = ETH_DST,
			pktLength = PKT_SIZE
		}
	end)
	if rc == "hw" then
		local bufs = mem:bufArray()
		if pattern ~= "cbr" then
			return log:error("HW only supports CBR")
		end
		queue:setRate(rate * (PKT_SIZE + 4) * 8)
		mg.sleepMillis(100) -- for good meaasure
		while mg.running() do
			bufs:alloc(PKT_SIZE)
			queue:send(bufs)
		end
	elseif rc == "sw" then
		-- larger batch size is useful when sending it through a rate limiter
		local bufs = mem:bufArray(128)
		local linkSpeed = txDev:getLinkStatus().speed
		while mg.running() do
			bufs:alloc(PKT_SIZE)
			if pattern == "custom" then
				for _, buf in ipairs(bufs) do
					buf:setDelay(rate * linkSpeed / 8)
				end
			end
			rateLimiter:send(bufs)
		end
	elseif rc == "moongen" then
		-- larger batch size is useful when sending it through a rate limiter
		local bufs = mem:bufArray(128)
		local dist = pattern == "poisson" and poissonDelay or function(x) return x end
		while mg.running() do
			bufs:alloc(PKT_SIZE)
			for _, buf in ipairs(bufs) do
				buf:setDelay(dist(10^10 / numThreads / 8 / (rate * 10^6) - PKT_SIZE - 24))
			end
			queue:sendWithDelay(bufs, rate * numThreads)
		end
	else
		log:error("Unknown rate control method")
	end
end


function dumpSlave(queue, threadId)
	snapLen = 60
	local mempool = memory.createMemPool()
	local bufs = mempool:bufArray(128)
	local pktCtr = stats:newPktRxCounter("Packets counted #".. threadId, "plain")
	file = "/home/guimvmatos/moongen3/MoonGen_Leris/guilherme3.pcap"
	writer = pcap:newWriter(file)
	while mg.running() do
		local rx = queue:tryRecv(bufs, 100)
		local batchTime = mg.getTime()
		for i = 1, rx do
			local buf = bufs[i]
			writer:writeBuf(batchTime, buf, snapLen)
			pktCtr:countPacket(buf)
		end
		bufs:free(rx)
		pktCtr:update()
	end
	pktCtr:finalize()
end

