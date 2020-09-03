/*
 * ao-servlet-firewall-path-space - Path space for servlet-based application request filtering.
 * Copyright (C) 2018, 2020  AO Industries, Inc.
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
 * along with ao-servlet-firewall-path-space.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aoindustries.servlet.firewall.pathspace;

import com.aoindustries.net.Path;
import com.aoindustries.net.pathspace.PathMatch;
import com.aoindustries.net.pathspace.PathSpace;
import com.aoindustries.net.pathspace.Prefix;
import com.aoindustries.net.pathspace.PrefixConflictException;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * Manages the allocation of the servlet {@link PathSpace path space} to registered
 * {@link FirewallComponent components}, creating per-module sets of firewall rules.
 * <p>
 * TODO: Should this be "ao-servlet-firewall-components"?
 * </p>
 */
public class FirewallPathSpace {

	@WebListener
	public static class Initializer implements ServletContextListener {
		@Override
		public void contextInitialized(ServletContextEvent event) {
			getInstance(event.getServletContext());
		}
		@Override
		public void contextDestroyed(ServletContextEvent event) {
			// Do nothing
		}
	}

	private static final String APPLICATION_ATTRIBUTE = FirewallPathSpace.class.getName();

	/**
	 * Gets the {@link FirewallPathSpace} for the given {@link ServletContext},
	 * creating a new instance if not yet present.
	 */
	public static FirewallPathSpace getInstance(ServletContext servletContext) {
		FirewallPathSpace instance = (FirewallPathSpace)servletContext.getAttribute(APPLICATION_ATTRIBUTE);
		if(instance == null) {
			instance = new FirewallPathSpace();
			servletContext.setAttribute(APPLICATION_ATTRIBUTE, instance);
			// TODO: How do we register this with global rules?
		}
		return instance;
	}

	private final PathSpace<FirewallComponent> pathSpace = new PathSpace<>();

	private FirewallPathSpace() {}

	/**
	 * Registers a new component.
	 *
	 * @see  PathSpace#put(com.aoindustries.net.pathspace.Prefix, java.lang.Object)
	 *
	 * @throws  PrefixConflictException  If the prefix conflicts with an existing entry.
	 *          TODO: At this time this means the component could be partially registered when it has multiple paths.
	 */
	public FirewallPathSpace add(FirewallComponent component) throws PrefixConflictException {
		for(Prefix prefix : component.getPrefixes()) {
			pathSpace.put(prefix, component);
		}
		// TODO: unregister prefixes added during partial add
		return this;
	}

	/**
	 * Registers any number of new components.
	 *
	 * @see  PathSpace#put(com.aoindustries.net.pathspace.Prefix, java.lang.Object)
	 *
	 * @throws  PrefixConflictException  If the prefix conflicts with an existing entry.
	 *          TODO: At this time this means the components could be partially registered when it has multiple paths.
	 */
	// TODO: Rename "register" or "allocate" to be more clear this is reserving a space?
	public FirewallPathSpace add(FirewallComponent ... components) throws PrefixConflictException {
		for(FirewallComponent component : components) {
			add(component);
		}
		return this;
	}

	// TODO: add overloads matching the static factory methods of FirewallComponent?
	//       Move those factory methods here instead, so there cannot be FirewallComponent in unregistered form?
	//       Remove varargs method and use method chaining if we go this route.

	// TODO: remove?

	/**
	 * Finds the component registered at the given path.
	 *
	 * @see  PathSpace#get(com.aoindustries.net.Path)
	 */
	public PathMatch<FirewallComponent> get(Path path) {
		return pathSpace.get(path);
	}
}
