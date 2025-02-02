local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"

local PKT_SIZE	= 60
local ETH_DST	= "ac:1f:6b:67:06:40"
local ip_src = "172.16.0.1"
local ip_dst = "172.16.0.2"

local function getRstFile(...)
	local args = { ... }
	for i, v in ipairs(args) do
		result, count = string.gsub(v, "%-%-result%=", "")
		if (count == 1) then
			return i, result
		end
	end
	return nil, nil
end

function configure(parser)
	parser:description("Generates bidirectional CBR traffic with hardware rate control and measure latencies.")
	parser:argument("dev1", "Device to transmit/receive from."):convert(tonumber)
	parser:argument("dev2", "Device to transmit/receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-f --file", "Filename of the latency histogram."):default("histogram.csv")
end

function master(args)
	local dev1 = device.config({port = args.dev1, rxQueues = 2, txQueues = 2})
	local dev2 = device.config({port = args.dev2, rxQueues = 2, txQueues = 2})
	device.waitForLinks()
	dev1:getTxQueue(0):setRate(args.rate)
	dev2:getTxQueue(0):setRate(args.rate)
	mg.startTask("loadSlave", dev1:getTxQueue(0))
	if dev1 ~= dev2 then
		mg.startTask("loadSlave", dev2:getTxQueue(0))
	end
	stats.startStatsTask{dev1, dev2}
	mg.startSharedTask("timerSlave", dev1:getTxQueue(1), dev2:getRxQueue(1), args.file)
	mg.waitForTasks()
end

function loadSlave(queue)
	local mem = memory.createMemPool(function(buf)
		buf:get5gPacket():fill{
			ethSrc = txDev,
			ethDst = ETH_DST,
			ethType = 0x8100,
			vlanTci = 0x4095,
			--vlanEther_type = 0x0800,
			vlanEther_type = 0x8100,
			macLcid = 0x0,
			macElcid = 0x0,
			rlcOct = 0,
			rlcSn = 0x0,
			rlcSo = 0x0,
			pdcpOct = 0x0,
			pdcpPdcp_sn = 0x0,
			ip4Src = ip_src,
			ip4Src = ip_dst,
			ip4ID = 1,
			ip4TTL = 64,
			ip4Protocol = 7,
			ip4Version = 4
		}
	end)
	local bufs = mem:bufArray()
	while mg.running() do
		bufs:alloc(PKT_SIZE)
		queue:send(bufs)
	end
end

function timerSlave(txQueue, rxQueue, histfile)
	local timestamper = ts:newTimestamper(txQueue, rxQueue)
	local hist = hist:new()
	mg.sleepMillis(1000) -- ensure that the load task is running
	while mg.running() do
		hist:update(timestamper:measureLatency(function(buf) buf:getVlanPacket().eth.dst:setString(ETH_DST) end))
	end
	hist:print()
	hist:save(histfile)
end

