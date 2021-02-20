package com.microsoft.authorise.tools;

import org.springframework.http.HttpStatus;

/**
 * Copyright 2013-2033 Estee Lauder(zgq65751348@gmail.com).
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.ydm01.com/index.do
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>
 *
 * @Auth Estee Lauder
 * @See {@code  }.
 * @Date 2021/2/20  14:47
 * </p>
 */
public class ResultUtils {

    public static JsonResult success() {
        JsonResult jsonResult = new JsonResult();
        jsonResult.setMessage(HttpStatus.OK.getReasonPhrase());
        jsonResult.setStatus(HttpStatus.OK.value());
        return jsonResult;
    }

    public static <T> JsonResult<T> success(T data) {
        JsonResult<T> jsonResult = new JsonResult<>();
        jsonResult.setMessage(HttpStatus.OK.getReasonPhrase());
        jsonResult.setStatus(HttpStatus.OK.value());
        jsonResult.setData(data);
        return jsonResult;
    }

    public static JsonResult fail(){
        JsonResult jsonResult = new JsonResult();
        jsonResult.setStatus(HttpStatus.FORBIDDEN.value());
        jsonResult.setMessage(HttpStatus.FORBIDDEN.getReasonPhrase());
        return jsonResult;
    }
}
