#!/bin/sh
# $Revision$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# (c) Tim Brown, 2012
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>

FILENAME="${1}"
if [ -f "${FILENAME}" ]
then
	filelength="`wc -l ${FILENAME} | awk '{ print $1 }'`"
	codechunk="`expr \"${filelength}\" - 20`"
	printf -- "= ${FILENAME} =\n"
	printf -- "\n";
	tail -n "${codechunk}" "${FILENAME}" | sed "s/%/%%/g" | while read line
	do
		if [ -n "`printf -- \"${line}\" | egrep \"^\\.\"`" ]
		then
			filename="`printf -- \"${line}\" | sed -e \"s/\\. //g\"`"
			printf -- "Depends on: `printf -- \"${filename}\"`\n"
			printf -- "\n"
		fi
		if [ -n "`printf -- \"${line}\" | egrep \"() {\"`" ]
		then
			functionname="`printf -- \"${line}\" | sed -e \"s/ () {//g\" -e \"s/%/%%/g\"`"
			printf -- "* ${functionname}\n"
			printf -- "\n"
		fi
		if [ -n "`printf -- \"${line}\" | egrep \"=\\".{[1-9]}\"`" ]
		then
			variablename="`printf -- \"${line}\" | cut -f 1 -d \"=\" | sed \"s/%/%%/g\"`"
			printf -- "    < ${variablename}\n"
			printf -- "\n"
		fi
		if [ -n "`printf -- \"${line}\" | egrep \"#\" | egrep -v \"^#$\"`" ]
		then
			if [ -n "`printf -- \"${line}\" | egrep \"#\" | egrep -v \"^#$\" | egrep \"TODO\"`" ]
			then
				comment="`printf -- \"${line}\" | sed -e \"s/.*# //g\" -e \"s/TODO //g\" -e \"s/%/%%/g\"`"
				printf -- "      <TODO>\n"
				printf -- "        ${comment}\n"
				printf -- "      </TODO>\n"
				printf -- "\n";
			else
				comment="`printf -- \"${line}\" | sed -e \"s/.*# //g\" -e \"s/%/%%/g\"`"
				printf -- "      <comment>\n"
				printf -- "        ${comment}\n"
				printf -- "      </comment>\n"
				printf -- "\n";
			fi
		fi
		if [ -n "`printf -- \"${line}\" | egrep \"error\"`" ]
		then
			errorstring="`printf \"${line}\" | cut -f 4 -d \"\\"\"`"
			printf -- "      <error>\n"
			printf -- "	   ${errorstring}\n"
			printf -- "      </error>\n"
			printf -- "\n"
		fi	
	done
fi
