# -*- coding: utf-8 -*-
import sys,os
from pyhcfs import parser


CURRENT_FILE_PATH = os.path.dirname(os.path.abspath(__file__))

class Parse_Meta(object):

    def __init__(self,meta_folder):

        if meta_type == 'old':
            self.meta_dir =  os.path.join(CURRENT_FILE_PATH, 'test_data/parse_meta/old')
        
        elif meta_type == 'new':
            self.meta_dir =  os.path.join(CURRENT_FILE_PATH, 'test_data/parse_meta/new')
        else:
            self.meta_dir = meta_type

    def list_vols(self,meta):
        
        meta_path = os.path.join(self.meta_dir, meta)
        meta_path = str.encode(meta_path)

        vols_from_parser = parser.list_volume(meta_path)

        print (vols_from_parser) 


    def parse_meta(self,meta):
        
        meta_path = os.path.join(self.meta_dir, meta)
        meta_path = str.encode(meta_path)

        meta = parser.parse_meta(meta_path)

        print (meta)

    def parse_childs(self,meta, offset=(0, 0), limit=100):
        
        meta_path = os.path.join(self.meta_dir, meta)
        meta_path = str.encode(meta_path)
        # add . and ..
        limit += 2
        data_from_parser = parser.list_dir_inorder(meta_path, offset, limit)

        print (data_from_parser)

    def list_file_blocks(self,meta):
       
        meta_path = os.path.join(self.meta_dir, meta)
        meta_path = str.encode(meta_path)
        data_from_parser = parser.list_file_blocks(meta_path)

        print (data_from_parser)

    def parse_vol_usage(self,meta):
       
        meta_path = os.path.join(self.meta_dir, meta)
        meta_path = str.encode(meta_path)
        data_from_parser = parser.get_vol_usage(meta_path)

        print(data_from_parser)


if __name__ == '__main__':

    meta_type = sys.argv[1]
    meta_name = sys.argv[2]
    function = sys.argv[3]

    parseWorker = Parse_Meta(str(meta_type))
    cmd = "parseWorker.{0}('{1}')".format(function,meta_name)
    eval(cmd)
 