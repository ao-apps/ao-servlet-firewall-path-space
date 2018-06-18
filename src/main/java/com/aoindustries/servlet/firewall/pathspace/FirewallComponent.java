/*
 * ao-servlet-firewall-path-space - Path space for servlet-based application request filtering.
 * Copyright (C) 2018  AO Industries, Inc.
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

import com.aoindustries.net.pathspace.PathSpace;
import com.aoindustries.net.pathspace.Prefix;
import com.aoindustries.servlet.firewall.api.Rule;
import com.aoindustries.util.AoCollections;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A {@link FirewallComponent} occupies one or more {@link Prefix prefixes} in the
 * servlet {@link PathSpace path space}.  It also has an associated list of per-component
 * {@link Rule rules}.  These rules are called after global rules for requests that
 * match the prefixes.
 * <p>
 * See <a href="../servlet-space">Servlet Space</a>.
 * TODO: Either move this page from semanticcms-core-controller, or link to it from here.
 * </p>
 */
// TODO: Per-component attributes?
public class FirewallComponent {

	public static FirewallComponent newInstance(Iterable<? extends Prefix> prefixes, Iterable<? extends Rule> rules) {
		FirewallComponent component = new FirewallComponent(prefixes);
		component.append(rules);
		return component;
	}

	public static FirewallComponent newInstance(Iterable<? extends Prefix> prefixes, Rule ... rules) {
		return newInstance(prefixes, Arrays.asList(rules));
	}

	public static FirewallComponent newInstance(Prefix[] prefixes, Iterable<? extends Rule> rules) {
		return newInstance(Arrays.asList(prefixes), rules);
	}

	public static FirewallComponent newInstance(Prefix[] prefixes, Rule ... rules) {
		return newInstance(Arrays.asList(prefixes), rules);
	}

	public static FirewallComponent newInstance(Prefix prefix, Iterable<? extends Rule> rules) {
		return newInstance(Collections.singleton(prefix), rules);
	}

	// TODO: Overloads taking String instead of Prefix, to avoid call to Prefix.valueOf
	public static FirewallComponent newInstance(Prefix prefix, Rule ... rules) {
		return newInstance(Collections.singleton(prefix), rules);
	}

	private final Set<Prefix> prefixes;

	private final List<Rule> rules = new CopyOnWriteArrayList<Rule>();

	private FirewallComponent(Iterable<? extends Prefix> prefixes) {
		this.prefixes = AoCollections.unmodifiableCopySet(prefixes);
		if(this.prefixes.isEmpty()) throw new IllegalArgumentException("prefixes is empty");
	}

	/**
	 * Gets an unmodifiable set of prefixes associated with this component.
	 */
	public Set<Prefix> getPrefixes() {
		return prefixes;
	}

	/**
	 * An unmodifiable wrapper around rules for {@link #getRules()}.
	 */
	private final List<Rule> unmodifiableRules = Collections.unmodifiableList(rules);

	/**
	 * Gets an unmodifiable copy of the rules applied to this component.
	 */
	public List<Rule> getRules() {
		return unmodifiableRules;
	}

	/**
	 * A small wrapper to prevent casting back to underlying list from the object
	 * returned from {@link #getRulesIterable()}.
	 */
	private final Iterable<Rule> rulesIter = new Iterable<Rule>() {
		@Override
		public Iterator<Rule> iterator() {
			return rules.iterator();
		}
	};

	/**
	 * Gets an unmodifiable iterator to the rules.
	 *
	 * @implNote  Is unmodifiable due to being implemented as {@link CopyOnWriteArrayList#iterator()}.
	 */
	public Iterable<Rule> getRulesIterable() {
		return rulesIter;
	}

	/**
	 * Inserts rules into the beginning of this component.
	 */
	public void prepend(Iterable<? extends Rule> rules) {
		this.rules.addAll(0, AoCollections.asCollection(rules));
	}

	/**
	 * Inserts rules into the beginning of this component.
	 */
	public void prepend(Rule ... rules) {
		prepend(Arrays.asList(rules));
	}

	/**
	 * Inserts rules into the end of this component.
	 */
	public void append(Iterable<? extends Rule> rules) {
		this.rules.addAll(AoCollections.asCollection(rules));
	}

	/**
	 * Inserts rules into the end of this component.
	 */
	public void append(Rule ... rules) {
		append(Arrays.asList(rules));
	}
}
