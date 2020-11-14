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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @author binchencoder
 */
@Controller
public class RegisterController {

  private static final Logger LOGGER = LoggerFactory.getLogger(RegisterController.class);

  /**
   * 表单登录页: <br/>
   *
   * 1. 已经登录用户重定向到默认页
   *
   * 2. 未登录用户，展示不同登录页
   */
  @RequestMapping(value = "/register", method = RequestMethod.GET)
  public String index(HttpServletRequest request, HttpServletResponse response, Model model) {

    LOGGER.info("To page {}", Routes.LOGIN_DEFAULT);
    return "regist/register.html";
  }
}
