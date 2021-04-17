@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("all_response",
			  SumStats::Key($host=c$id$orig_h), 
			  SumStats::Observation($num=1));
	if (code == 404)
	{
		SumStats::observe("404_response", 
			          SumStats::Key($host=c$id$orig_h),
			          SumStats::Observation($num=1));
    		SumStats::observe("url_response_404", 
    			          SumStats::Key($host=c$id$orig_h), 
    			          SumStats::Observation($str=c$http$uri));
    	}
}	      
event zeek_init()
{
   
    local r1 = SumStats::Reducer($stream="all_response",
    				 $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="404_response", 	
    				 $apply=set(SumStats::SUM));    
    local r3 = SumStats::Reducer($stream="url_response_404", 
        	                 $apply=set(SumStats::UNIQUE));  

    SumStats::create([$name = "test",
                      $epoch = 10min,
                      $reducers = set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
           		{
	                        local r1_result=result["all_response"];
	                        local r2_result=result["404_response"];
	                        local r3_result=result["url_response_404"];
	                        if(r2_result$sum>2 && r2_result$sum/r1_result$sum>0.2)
		                    {
		                    	if(r3_result$unique/r2_result$sum>0.5)
		                        {
		                        	print fmt("%s is a scanner with %d scan attemps on %d urls”",key$host ,r2_result$sum,r3_result$unique);
		                        }
		                    }
                        }]);
}
