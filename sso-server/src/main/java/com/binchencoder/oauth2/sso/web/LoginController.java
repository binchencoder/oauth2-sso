/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binchencoder.oauth2.sso.web;

import com.binchencoder.oauth2.sso.route.Routes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author binchencoder
 */
@Controller
public class LoginController {

  @GetMapping(Routes.DEFAULT)
  public String root() {
    return "index";
  }
//
//	@GetMapping("/index")
//	public String index() {
//		return "index";
//	}

//  @GetMapping(Routes.LOGIN)
//  public String login() {
//    return "login";
//  }

//	@GetMapping("/login-error")
//	public String loginError(Model model) {
//		model.addAttribute("loginError", true);
//		return login();
//	}
}
