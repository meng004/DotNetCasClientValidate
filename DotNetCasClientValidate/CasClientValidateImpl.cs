using System;
using System.Net;
using System.Web;
using System.Xml;

namespace DotNetCasClientValidate
{
    public class CasClientValidateImpl
    {

        #region 属性

        /// <summary>
        /// http请求
        /// </summary>
        readonly HttpRequest _request;
        /// <summary>
        /// http响应
        /// </summary>
        readonly HttpResponse _response;
        /// <summary>
        /// cas认证服务器地址
        /// </summary>
        readonly string _casLoginUrl;

        #endregion

        #region 构造函数

        /// <summary>
        /// 接收外部传入
        /// </summary>
        /// <param name="httpContext">web上下文</param>
        /// <param name="casLoginUrl">cas认证地址</param>
        public CasClientValidateImpl(HttpRequest request, HttpResponse response, string casLoginUrl)
        {
            _request = request;
            _response = response;
            _casLoginUrl = casLoginUrl;

        }

        public CasClientValidateImpl(HttpContext context, string casLoginUrl)
        {
            _request = context.Request;
            _response = context.Response;
            _casLoginUrl = casLoginUrl;
        }
        #endregion

        #region 登录、登出

        /// <summary>
        /// Cas单点登录
        /// </summary>
        public string Authenticate()
        {

            //获取ticket
            string ticket = _request.QueryString["ticket"];
            //获取url地址
            var url = _request.Url.ToString();

            //重定向到CAS认证服务器
            if (ticket == null || ticket.Length == 0)
            {

                string redir = string.Format("{0}login?service={1}", _casLoginUrl, url);
                _response.Redirect(redir);
                return string.Empty;
            }
            else
            {

                //验证url
                if (url.Contains("?ticket="))
                {
                    var index = url.IndexOf("?ticket=");
                }
                
                var newurl = url.Remove(url.IndexOf("?ticket="), 8 + ticket.Length);

                string validateUrl = string.Format("{0}serviceValidate?ticket={1}&service={2}", _casLoginUrl, ticket, newurl);
                //string validateUrl = string.Format("{0}serviceValidate?service={1}", _casLoginUrl, url);

                

                //读取基于ssl的xml
                ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;

                //读取返回的用户名
                using (WebClient webClient = new WebClient())
                {

                    //////从CAS验证返回信息中读取字节流
                    //StreamReader reader = new StreamReader(webClient.OpenRead(validateUrl));
                    //////保存到字符串
                    //string resp = reader.ReadToEnd();
                    //////关闭阅读器
                    //reader.Close();

                    //////将字符串转换为XML
                    //NameTable nt = new NameTable();
                    //XmlNamespaceManager nsMgr = new XmlNamespaceManager(nt);
                    //XmlParserContext context = new XmlParserContext(null, nsMgr, null, XmlSpace.None);
                    //XmlTextReader xmlReader = new XmlTextReader(resp, XmlNodeType.Element, context);

                    ////读取用户数字身份证Id
                    //string netId = string.Empty;
                    //while (xmlReader.Read())
                    //{
                    //    if (xmlReader.IsStartElement())
                    //    {
                    //        string tag = xmlReader.LocalName;
                    //        if (tag == "user")
                    //        {
                    //            netId = xmlReader.ReadString();
                    //            break;
                    //        }
                    //    }
                    //}

                    //关闭阅读器
                    //xmlReader.Close();

                    //读取用户数字身份证Id
                    string netId = string.Empty;

                    //读取cas返回消息

                    XmlTextReader reader = new XmlTextReader(validateUrl);
                    while (reader.Read())
                    {
                        if (reader.IsStartElement())
                        {
                            if (reader.LocalName == "user")
                            {
                                netId = reader.ReadString();
                                break;
                            }
                        }
                    }
                    //关闭阅读器
                    reader.Close();

                    //返回用户数字身份信息
                    if (string.IsNullOrWhiteSpace(netId))
                    {
                        _response.Write("未通过验证");
                        return string.Empty;
                    }
                    else
                    {
                        //返回数字身份证号
                        return netId;
                    }
                }
            }

        }

        /// <summary>
        /// Cas单点登出
        /// </summary>
        public void SignOut()
        {
            string redirectUrl = string.Format("{0}logout", _casLoginUrl);
            _response.Redirect(redirectUrl);
        }


        #endregion

    }
}
