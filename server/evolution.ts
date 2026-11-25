// Adapter foundation. Not exposed to users until instance ownership and consent checks are implemented.
export async function evolutionStatus(instance:string){
 const base=process.env.EVOLUTION_URL,key=process.env.EVOLUTION_API_KEY;
 if(!base||!key)throw Error('Evolution not configured');
 const url=new URL(base);if(url.protocol!=='https:')throw Error('HTTPS required');
 const response=await fetch(base.replace(/\/$/,'')+'/instance/connectionState/'+encodeURIComponent(instance),{headers:{apikey:key},redirect:'error',signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw Error('Evolution request failed');return response.json();
}
