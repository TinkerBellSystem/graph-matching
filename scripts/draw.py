# Author: Xueyuan Michael Han <hanx@g.harvard.edu>
#
# Copyright (C) 2018 Harvard University, University of Cambridge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

import os, sys

dot_files = os.listdir("../dot")	# The training file names within that directory.
for dot_file in dot_files:
	hookname = dot_file.split('.')[0]
	dot_file_path = os.path.join("../dot", dot_file)
	os.system('dot -Tpng ' + dot_file_path + ' -o ../img/'+ hookname +'.png')
