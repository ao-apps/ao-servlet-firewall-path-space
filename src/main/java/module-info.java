/*
 * ao-servlet-firewall-path-space - Path space for servlet-based application request filtering.
 * Copyright (C) 2021  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-servlet-firewall-path-space.
 *
 * ao-servlet-firewall-path-space is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-servlet-firewall-path-space is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-servlet-firewall-path-space.  If not, see <https://www.gnu.org/licenses/>.
 */
module com.aoapps.servlet.firewall.pathspace {
	exports com.aoapps.servlet.firewall.pathspace;
	// Direct
	requires com.aoapps.collections; // <groupId>com.aoapps</groupId><artifactId>ao-collections</artifactId>
	requires com.aoapps.hodgepodge; // <groupId>com.aoapps</groupId><artifactId>ao-hodgepodge</artifactId>
	requires com.aoapps.lang; // <groupId>com.aoapps</groupId><artifactId>ao-lang</artifactId>
	requires com.aoapps.net.pathspace; // <groupId>com.aoapps</groupId><artifactId>ao-net-path-space</artifactId>
	requires com.aoapps.net.types; // <groupId>com.aoapps</groupId><artifactId>ao-net-types</artifactId>
	requires com.aoapps.servlet.firewall.api; // <groupId>com.aoapps</groupId><artifactId>ao-servlet-firewall-api</artifactId>
	requires com.aoapps.servlet.util; // <groupId>com.aoapps</groupId><artifactId>ao-servlet-util</artifactId>
	requires javax.servlet.api; // <groupId>javax.servlet</groupId><artifactId>javax.servlet-api</artifactId>
}
