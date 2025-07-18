import json
from ryu.app.wsgi import ControllerBase, route, Response

from policy_maker import Policy

class BlockServer(ControllerBase):
    '''
    Handles external block/unblock requests using REST
        - POST /blocklist   -> add a block
        - DELETE /blocklist -> removes a block
        - GET /blocklist    -> lists all blocks
    '''

    def __init__(self, req, link, data):
        super().__init__(req, link, data)
        
        # Reference to main app controller.py
        self.controller = data['controller']
        self.queue = data['queue'] 

    @route(name= 'block', path= '/blocklist', methods=['POST'])
    def add_block(self, req):
        try: 
            body = req.json_body

            dpid = body.get('dpid')
            src = body.get('eth_src')
            dst = body.get('eth_dst') if body.get('eth_dst') else None

            self.queue.put(Policy(dpid, src, dst, -1, True))


            return Response(status=201) #created
        except Exception as e:
            return Response(body=str(e), status = 400)
    
    @route(name= 'block', path= '/blocklist', methods=['DELETE'])
    def remove_block(self, req):
        try: 
            body = req.json_body

            dpid = body.get('dpid')
            src = body.get('eth_src')
            dst = body.get('eth_dst') if body.get('eth_dst') else None

            self.queue.put(Policy(dpid, src, dst, -1, False))

            return Response(status=200) #done
        except Exception as e:
            return Response(body=str(e), status = 400)
        
    @route(name= 'block', path= '/blocklist', methods=['GET'])
    def list_block(self, req):
        
        blocklist = []
        for (dpid, src, dst) in self.controller.blocklist.values():
            blocklist.append({
                'dpid': dpid,
                'eth_src': src,
                'eth_dst': dst
            })

        body = json.dumps(blocklist, indent = 2) + "\n"

        return Response(body=body, content_type='application/json')