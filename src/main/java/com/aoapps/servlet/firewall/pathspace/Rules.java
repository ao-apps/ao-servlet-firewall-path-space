/*
 * ao-servlet-firewall-path-space - Path space for servlet-based application request filtering.
 * Copyright (C) 2018, 2020, 2021, 2022  AO Industries, Inc.
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

package com.aoapps.servlet.firewall.pathspace;

import static com.aoapps.servlet.firewall.api.MatcherUtil.callRules;
import static com.aoapps.servlet.firewall.api.MatcherUtil.doMatches;

import com.aoapps.hodgepodge.util.WildcardPatternMatcher;
import com.aoapps.lang.validation.ValidationException;
import com.aoapps.net.Path;
import com.aoapps.net.pathspace.PathMatch;
import com.aoapps.net.pathspace.PathSpace;
import com.aoapps.net.pathspace.Prefix;
import com.aoapps.servlet.firewall.api.Action;
import com.aoapps.servlet.firewall.api.FirewallContext;
import com.aoapps.servlet.firewall.api.Matcher;
import com.aoapps.servlet.firewall.api.Matcher.Result;
import com.aoapps.servlet.firewall.api.Rule;
import com.aoapps.servlet.http.Dispatcher;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

/**
 * A set of {@link Matcher} and {@link Action} implementations for {@link PathSpace} and {@link PathMatch}.
 * <p>
 * <b>Implementation Note:</b><br>
 * This is admittedly overload-heavy.  We are paying the price here in order to have the absolutely
 * cleanest possible rule definitions.  Perhaps a future version of Java will introduce optional parameters
 * and this can be cleaned-up some.
 * </p>
 */
public final class Rules {

  /** Make no instances. */
  private Rules() {
    throw new AssertionError();
  }

  // <editor-fold defaultstate="collapsed" desc="pathSpace">
  /**
   * See {@link FirewallPathSpace}.
   */
  public static final class pathSpace {

    /** Make no instances. */
    private pathSpace() {
      throw new AssertionError();
    }

    /**
     * Locates any registered {@link FirewallComponent} and invokes its
     * {@link FirewallComponent#getRules() set of firewall rules}.
     * <p>
     * TODO: Define how servlet path is determined.  Especially regarding include/forward and pathInfo.
     * </p>
     * <p>
     * <b>Implementation Note:</b><br>
     * Sets the {@link FirewallContext} attribute {@link pathMatch#PATH_MATCH_CONTEXT_KEY}
     * before invoking the component rules.  Restores its previous value when done.
     * </p>
     * <p>
     * <b>Returns:</b><br>
     * {@link Result#TERMINATE} when component found and it performed a terminating {@link Action}.<br>
     * {@link Result#MATCH} when a component is found and rule traversal has been completed without any terminating {@link Action}.<br>
     * {@link Result#NO_MATCH} when no component matches the current servlet path.
     * </p>
     *
     * @see  Dispatcher#getCurrentPagePath(javax.servlet.http.HttpServletRequest)
     */
    public static final Matcher doFirewallComponent = (context, request) -> {
      try {
        // TODO: What to do with pathInfo, forward, include?
        FirewallPathSpace pathSpace = FirewallPathSpace.getInstance(request.getServletContext());
        PathMatch<FirewallComponent> match = pathSpace.get(Path.valueOf(Dispatcher.getCurrentPagePath(request)));
        if (match == null) {
          return Result.NO_MATCH;
        } else {
          final Object oldValue = context.getAttribute(pathMatch.PATH_MATCH_CONTEXT_KEY);
          try {
            context.setAttribute(pathMatch.PATH_MATCH_CONTEXT_KEY, match);
            return callRules(context, match.getValue().getRulesIterable(), Result.MATCH);
          } finally {
            context.setAttribute(pathMatch.PATH_MATCH_CONTEXT_KEY, oldValue);
          }
        }
      } catch (ValidationException e) {
        throw new ServletException(e);
      }
    };
  }

  // </editor-fold>

  // <editor-fold defaultstate="collapsed" desc="pathMatch">
  /**
   * See {@link PathMatch}.
   */
  public static final class pathMatch {

    /** Make no instances. */
    private pathMatch() {
      throw new AssertionError();
    }

    /**
     * The firewall context key that holds the current {@link PathMatch}.
     */
    // TODO: Make a FirewallScope that extends Scope, much like Scope.Request and Scope.REQUEST
    private static final String PATH_MATCH_CONTEXT_KEY = pathMatch.class.getName();

    /**
     * Gets the {@link PathMatch} for the current servlet space.
     *
     * @throws ServletException when no {@link PathMatch} set.
     */
    private static PathMatch<FirewallComponent> getPathMatch(FirewallContext context) throws ServletException {
      @SuppressWarnings("unchecked")
      PathMatch<FirewallComponent> pathMatch = (PathMatch<FirewallComponent>) context.getAttribute(PATH_MATCH_CONTEXT_KEY);
      if (pathMatch == null) {
        throw new ServletException("PathMatch not set on firewall context");
      }
      return pathMatch;
    }

    private abstract static class PathMatchMatcher implements Matcher {
      @Override
      public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
        PathMatch<FirewallComponent> pathMatch = getPathMatch(context);
        if (
            matches(
                context,
                request,
                pathMatch.getPrefix(),
                pathMatch.getPrefixPath(),
                pathMatch.getPath()
            )
        ) {
          return Result.MATCH;
        } else {
          return Result.NO_MATCH;
        }
      }

      /**
       * See {@link #perform(com.aoapps.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)}.
       *
       * @param  prefix  See {@link PathMatch#getPrefix()}
       * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
       * @param  path  See {@link PathMatch#getPath()}
       */
      protected abstract boolean matches(
          FirewallContext context,
          HttpServletRequest request,
          Prefix prefix,
          Path prefixPath,
          Path path
      ) throws IOException, ServletException;
    }

    private abstract static class PathMatchMatcherWithRules implements Matcher {

      private final Iterable<? extends Rule> rules;

      private PathMatchMatcherWithRules(Iterable<? extends Rule> rules) {
        this.rules = rules;
      }

      //private PathMatchMatcherWithRules(Rule ... rules) {
      //  this(Arrays.asList(rules));
      //}

      @Override
      public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
        PathMatch<FirewallComponent> pathMatch = getPathMatch(context);
        return doMatches(
            matches(
                context,
                request,
                pathMatch.getPrefix(),
                pathMatch.getPrefixPath(),
                pathMatch.getPath()
            ),
            context,
            rules
        );
      }

      /**
       * See {@link #perform(com.aoapps.servlet.firewall.rules.FirewallContext, javax.servlet.http.HttpServletRequest)}.
       *
       * @param  prefix  See {@link PathMatch#getPrefix()}
       * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
       * @param  path  See {@link PathMatch#getPath()}
       */
      protected abstract boolean matches(
          FirewallContext context,
          HttpServletRequest request,
          Prefix prefix,
          Path prefixPath,
          Path path
      ) throws IOException, ServletException;
    }

    private abstract static class PathMatchMatcherWithRulesAndOtherwise implements Matcher {

      private final Iterable<? extends Rule> rules;
      private final Iterable<? extends Rule> otherwise;

      private PathMatchMatcherWithRulesAndOtherwise(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        this.rules = rules;
        this.otherwise = otherwise;
      }

      //private PathMatchMatcherWithRulesAndOtherwise(Rule[] rules, Rule ... otherwise) {
      //  this(Arrays.asList(rules), Arrays.asList(otherwise));
      //}

      @Override
      public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
        PathMatch<FirewallComponent> pathMatch = getPathMatch(context);
        return doMatches(
            matches(
                context,
                request,
                pathMatch.getPrefix(),
                pathMatch.getPrefixPath(),
                pathMatch.getPath()
            ),
            context,
            rules,
            otherwise
        );
      }

      /**
       * See {@link #perform(com.aoapps.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)}.
       *
       * @param  prefix  See {@link PathMatch#getPrefix()}
       * @param  prefixPath  See {@link PathMatch#getPrefixPath()}
       * @param  path  See {@link PathMatch#getPath()}
       */
      protected abstract boolean matches(
          FirewallContext context,
          HttpServletRequest request,
          Prefix prefix,
          Path prefixPath,
          Path path
      ) throws IOException, ServletException;
    }

    // <editor-fold defaultstate="collapsed" desc="prefix">
    /**
     * See {@link PathMatch#getPrefix()}.
     */
    public static final class prefix {

      /** Make no instances. */
      private prefix() {
        throw new AssertionError();
      }

      /**
       * Matches when a request prefix starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return matchPrefix.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return matchPrefix.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return matchPrefix.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule ... rules) {
        if (rules.length == 0) {
          return startsWith(prefix);
        }
        return startsWith(prefix, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return startsWith(prefix, rules);
        }
        return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return matchPrefix.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return matchPrefix.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule ... rules) {
        if (rules.length == 0) {
          return endsWith(suffix);
        }
        return endsWith(suffix, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return endsWith(suffix, rules);
        }
        return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule ... rules) {
        if (rules.length == 0) {
          return contains(substring);
        }
        return contains(substring, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return contains(substring, rules);
        }
        return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @see  Prefix#equals(java.lang.Object)
       */
      public static Matcher equals(final Prefix target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Prefix#equals(java.lang.Object)
       */
      public static Matcher equals(final Prefix target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Prefix#equals(java.lang.Object)
       */
      public static Matcher equals(final Prefix target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Prefix#equals(java.lang.Object)
       */
      public static Matcher equals(Prefix target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Prefix#equals(java.lang.Object)
       */
      public static Matcher equals(Prefix target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @see  Prefix#valueOf(java.lang.String)
       */
      public static Matcher equals(String target) {
        return equals(Prefix.valueOf(target));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Prefix#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules) {
        return equals(Prefix.valueOf(target), rules);
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Prefix#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return equals(Prefix.valueOf(target), rules, otherwise);
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Prefix#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule ... rules) {
        return equals(Prefix.valueOf(target), rules);
      }

      /**
       * Matches when a request prefix is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Prefix#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(Prefix.valueOf(target), rules, otherwise);
      }

      /**
       * Matches when a request prefix is equal to a given character sequence, case-sensitive.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-insensitive.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefix.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
        if (rules.length == 0) {
          return equalsIgnoreCase(target);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equalsIgnoreCase(target, rules);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix matches a given regular expression.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefix.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefix.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefix.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(pattern);
        }
        return matches(pattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(pattern, rules);
        }
        return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       * <p>
       * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger ao-hodgepodge project.
       * </p>
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefix.toString());
          }
        };
      }

      /**
       * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefix.toString());
          }
        };
      }

      /**
       * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefix.toString());
          }
        };
      }

      /**
       * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(wildcardPattern);
        }
        return matches(wildcardPattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(wildcardPattern, rules);
        }
        return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }
    }

    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc="prefixPath">
    /**
     * See {@link PathMatch#getPrefixPath()}.
     */
    public static final class prefixPath {

      /** Make no instances. */
      private prefixPath() {
        throw new AssertionError();
      }

      /**
       * Matches when a request prefix path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return prefixPath.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return prefixPath.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return prefixPath.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request prefix path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule ... rules) {
        if (rules.length == 0) {
          return startsWith(prefix);
        }
        return startsWith(prefix, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return startsWith(prefix, rules);
        }
        return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request prefix path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule ... rules) {
        if (rules.length == 0) {
          return endsWith(suffix);
        }
        return endsWith(suffix, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return endsWith(suffix, rules);
        }
        return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request prefix path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule ... rules) {
        if (rules.length == 0) {
          return contains(substring);
        }
        return contains(substring, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return contains(substring, rules);
        }
        return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.equals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(Path target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(Path target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target) {
        try {
          return equals(Path.valueOf(target));
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules) {
        try {
          return equals(Path.valueOf(target), rules);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        try {
          return equals(Path.valueOf(target), rules, otherwise);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule ... rules) {
        try {
          return equals(Path.valueOf(target), rules);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
        try {
          return equals(Path.valueOf(target), rules, otherwise);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-insensitive.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return prefixPath.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
        if (rules.length == 0) {
          return equalsIgnoreCase(target);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equalsIgnoreCase(target, rules);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path matches a given regular expression.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefixPath.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefixPath.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(prefixPath.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(pattern);
        }
        return matches(pattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(pattern, rules);
        }
        return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       * <p>
       * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger ao-hodgepodge project.
       * </p>
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefixPath.toString());
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefixPath.toString());
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(prefixPath.toString());
          }
        };
      }

      /**
       * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(wildcardPattern);
        }
        return matches(wildcardPattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request prefix path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(wildcardPattern, rules);
        }
        return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }
    }

    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc="path">
    /**
     * See {@link PathMatch#getPath()}.
     */
    public static final class path {

      /** Make no instances. */
      private path() {
        throw new AssertionError();
      }

      /**
       * Matches when a request path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return path.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return path.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix matchPrefix, Path prefixPath, Path path) {
            return path.toString().startsWith(prefix);
          }
        };
      }

      /**
       * Matches when a request path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule ... rules) {
        if (rules.length == 0) {
          return startsWith(prefix);
        }
        return startsWith(prefix, Arrays.asList(rules));
      }

      /**
       * Matches when a request path starts with a given string, case-sensitive.
       * Matches when prefix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#startsWith(java.lang.String)
       */
      public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return startsWith(prefix, rules);
        }
        return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().endsWith(suffix);
          }
        };
      }

      /**
       * Matches when a request path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule ... rules) {
        if (rules.length == 0) {
          return endsWith(suffix);
        }
        return endsWith(suffix, Arrays.asList(rules));
      }

      /**
       * Matches when a request path ends with a given string, case-sensitive.
       * Matches when suffix is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#endsWith(java.lang.String)
       */
      public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return endsWith(suffix, rules);
        }
        return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contains(substring);
          }
        };
      }

      /**
       * Matches when a request path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule ... rules) {
        if (rules.length == 0) {
          return contains(substring);
        }
        return contains(substring, Arrays.asList(rules));
      }

      /**
       * Matches when a request path contains a given character sequence, case-sensitive.
       * Matches when substring is empty.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contains(java.lang.CharSequence)
       */
      public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return contains(substring, rules);
        }
        return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.equals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.equals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(final Path target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.equals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(Path target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#equals(java.lang.Object)
       */
      public static Matcher equals(Path target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target) {
        try {
          return equals(Path.valueOf(target));
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules) {
        try {
          return equals(Path.valueOf(target), rules);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        try {
          return equals(Path.valueOf(target), rules, otherwise);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule ... rules) {
        try {
          return equals(Path.valueOf(target), rules);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      // TODO: Support a "map" instead of just "equals", to avoid sequential lookups when there are a large number of different specific targets.

      /**
       * Matches when a request path is equal to a given string, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Path#valueOf(java.lang.String)
       */
      public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
        try {
          return equals(Path.valueOf(target), rules, otherwise);
        } catch (ValidationException e) {
          throw new IllegalArgumentException(e);
        }
      }

      /**
       * Matches when a request path is equal to a given character sequence, case-sensitive.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().contentEquals(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule ... rules) {
        if (rules.length == 0) {
          return equals(target);
        }
        return equals(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request path is equal to a given character sequence, case-sensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#contentEquals(java.lang.CharSequence)
       */
      public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equals(target, rules);
        }
        return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path is equal to a given string, case-insensitive.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return path.toString().equalsIgnoreCase(target);
          }
        };
      }

      /**
       * Matches when a request path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
        if (rules.length == 0) {
          return equalsIgnoreCase(target);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules));
      }

      /**
       * Matches when a request path is equal to a given string, case-insensitive.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  String#equalsIgnoreCase(java.lang.String)
       */
      public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return equalsIgnoreCase(target, rules);
        }
        return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path matches a given regular expression.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(path.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(path.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return pattern.matcher(path.toString()).matches();
          }
        };
      }

      /**
       * Matches when a request path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(pattern);
        }
        return matches(pattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request path matches a given regular expression.
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  Pattern#compile(java.lang.String)
       * @see  Pattern#compile(java.lang.String, int)
       */
      public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(pattern, rules);
        }
        return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }

      /**
       * Matches when a request path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       * <p>
       * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger ao-hodgepodge project.
       * </p>
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
        return new PathMatchMatcher() {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(path.toString());
          }
        };
      }

      /**
       * Matches when a request path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
        return new PathMatchMatcherWithRules(rules) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(path.toString());
          }
        };
      }

      /**
       * Matches when a request path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
        return new PathMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
          @Override
          protected boolean matches(FirewallContext context, HttpServletRequest request, Prefix prefix, Path prefixPath, Path path) {
            return wildcardPattern.isMatch(path.toString());
          }
        };
      }

      /**
       * Matches when a request path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
        if (rules.length == 0) {
          return matches(wildcardPattern);
        }
        return matches(wildcardPattern, Arrays.asList(rules));
      }

      /**
       * Matches when a request path matches a given {@link WildcardPatternMatcher}.
       * <p>
       * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
       * especially in suffix matching.
       * </p>
       *
       * @param  rules  Invoked only when matched.
       * @param  otherwise  Invoked only when not matched.
       *
       * @see  WildcardPatternMatcher#compile(java.lang.String)
       */
      public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
        if (otherwise.length == 0) {
          return matches(wildcardPattern, rules);
        }
        return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
      }
    }

    // TODO: PathMatch-compatible for non-servlet-space root? (/**, /, /servlet-path)?

    // TODO: String.regionMatches?

    // TODO: More case-insensitive of the above?

    // TODO: CompareTo for before/after/ <= , >= ?

    // </editor-fold>
  }
  // </editor-fold>
}
