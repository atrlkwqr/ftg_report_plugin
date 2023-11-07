(function() {
    if (window.hasRun) {
        return;
    }
    window.hasRun = true;

    const currentURL = window.location.href;
    if (!currentURL.match(/^https:\/\/findthegap\.co\.kr\/program\/.+\/report$/)) {
        return;
    }

    const vulnTypes = {
        "xss": "Cross-Site Scripting (XSS) allows attackers to execute scripts in the victim's browser which can hijack user sessions, deface websites, or redirect the user to malicious sites.",
        "sqli": "SQL Injection (SQLi) is a type of attack that allows the attacker to execute arbitrary SQL code on a database. This can lead to data being deleted or stolen from the database.",
        "ssrf": "Server Side Request Forgery (SSRF) is a type of attack where an attacker can make a request to internal resources behind a firewall.",
        "rce": "Remote Code Execution (RCE) allows an attacker to execute arbitrary code on a victim machine."
    };

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function clickFirstElement(xpath) {
        var firstElement = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
        if (firstElement) {
            firstElement.click();
            return true;
        } else {
            console.error('First element not found');
            return false;
        }
    }
    
    async function selectSecondElement(xpath) {
        await sleep(1000);
        var secondElement = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
        if (secondElement) {
        secondElement.click();
        } else {
        console.error('Second element not found');
        }
    }

    function setTextareaValue(textareaElement, value) {
        textareaElement.value = value;
        textareaElement.dispatchEvent(new Event('input', { bubbles: true }));
        textareaElement.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function extractDomain(url) {
        const parsedUrl = new URL(url);
        return parsedUrl.hostname;
    }    

    async function fillForm() {
        const vulnerabilityType = prompt("Choose vulnerability type: xss, sqli, ssrf, rce");
        if (!vulnTypes[vulnerabilityType]) {
            alert("Invalid vulnerability type chosen!");
            return;
        }

        const VulnURL = prompt("Input vulnerability API ex) https://example.com/?param1=test");

        await sleep(1000);

        // 범위 완료
        if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[3]/div/div/div')) {
            let i = 0;
            while (true) {
                const xpath = `//*[@id="root"]/section/section/div/div[3]/div[2]/div[3]/div/div[${i+2}]/div/p`;
                let result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                let node = result.singleNodeValue;
                const domainToCheck = await extractDomain(VulnURL);
        
                if (node !== null && node.textContent.includes(domainToCheck)) {
                    await selectSecondElement(xpath);
                } else {
                    console.log("도메인 선택할 수 없음");
                    break;
                }
                i++;
            }
        }
        

        await sleep(1000);

        // 공격 유형 완료
        if (vulnerabilityType.toLowerCase() === "xss") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div[2]/div[35]');
            }   
        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div[2]/div[37]');
            }  
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div[2]/div[28]');
            }
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div[2]/div[38]');
            }  
        }
        else {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[5]/div/div[2]/div[47]');
            }  
        }

        await sleep(1000);

        // 공격 영향 완료
        if (vulnerabilityType.toLowerCase() === "xss") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div[2]/div[1]');
            }   
        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div[2]/div[1]');
            }  
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div[2]/div[9]');
            }
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div[2]/div[6]');
            }  
        }
        else {
            if (await clickFirstElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div/div')) {
                await selectSecondElement('//*[@id="root"]/section/section/div/div[3]/div[2]/div[6]/div/div[2]/div[9]');
            }  
        }

        await sleep(1000);

        // 윤리적 해커 자체 평가 네트워크 클릭 완료

        var xpath_1_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[1]/div/button[1]';
        var button_1_1 = document.evaluate(xpath_1_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_1_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[1]/div/button[2]';
        var button_1_2 = document.evaluate(xpath_1_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_1_3 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[1]/div/button[3]';
        var button_1_3 = document.evaluate(xpath_1_3, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_1_4 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[1]/div/button[4]';
        var button_1_4 = document.evaluate(xpath_1_4, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_2_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[1]/div/button[1]';
        var button_2_1 = document.evaluate(xpath_2_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_2_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[1]/div/button[2]';
        var button_2_2 = document.evaluate(xpath_2_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_3_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[2]/div/button[1]';
        var button_3_1 = document.evaluate(xpath_3_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_3_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[2]/div/button[2]';
        var button_3_2 = document.evaluate(xpath_3_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_4_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[2]/div/button[1]';
        var button_4_1 = document.evaluate(xpath_4_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_4_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[2]/div/button[2]';
        var button_4_2 = document.evaluate(xpath_4_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_4_3 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[2]/div/button[3]';
        var button_4_3 = document.evaluate(xpath_4_3, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_5_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[3]/div/button[1]';
        var button_5_1 = document.evaluate(xpath_5_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_5_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[3]/div/button[2]';
        var button_5_2 = document.evaluate(xpath_5_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_5_3 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[3]/div/button[3]';
        var button_5_3 = document.evaluate(xpath_5_3, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_6_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[3]/div/button[1]';
        var button_6_1 = document.evaluate(xpath_6_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_6_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[3]/div/button[2]';
        var button_6_2 = document.evaluate(xpath_6_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_6_3 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[3]/div/button[3]';
        var button_6_3 = document.evaluate(xpath_6_3, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_7_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[4]/div/button[1]';
        var button_7_1 = document.evaluate(xpath_7_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_7_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[1]/div[4]/div/button[2]';
        var button_7_2 = document.evaluate(xpath_7_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_8_1 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[4]/div/button[1]';
        var button_8_1 = document.evaluate(xpath_8_1, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_8_2 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[4]/div/button[2]';
        var button_8_2 = document.evaluate(xpath_8_2, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        var xpath_8_3 = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[7]/div[2]/div[1]/div/div[2]/div[4]/div/button[3]';
        var button_8_3 = document.evaluate(xpath_8_3, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;


        if (vulnerabilityType.toLowerCase() === "xss") {
    
            button_1_1.click();
            button_2_2.click();
            button_3_2.click();
            button_4_2.click();
            button_5_1.click();
            button_6_2.click();
            button_7_2.click();
            button_8_2.click();

        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {

            button_1_1.click();
            button_2_2.click();
            button_3_2.click();
            button_4_3.click();
            button_5_1.click();
            button_6_2.click();
            button_7_1.click();
            button_8_2.click();
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {

            button_1_1.click();
            button_2_2.click();
            button_3_2.click();
            button_4_1.click();
            button_5_1.click();
            button_6_3.click();
            button_7_1.click();
            button_8_2.click();
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {

            button_1_1.click();
            button_2_2.click();
            button_3_2.click();
            button_4_3.click();
            button_5_2.click();
            button_6_3.click();
            button_7_1.click();
            button_8_3.click();

        }
        else {
            button_1_1.click();
            button_2_2.click();
            button_3_2.click();
            button_4_1.click();
            button_5_2.click();
            button_6_1.click();
            button_7_2.click();
            button_8_1.click();
        }

        await sleep(1000);

        // 취약점 설명 완료

        const vulnerabilityDetail = document.querySelector("div[name='vulnerabilityDetail'] .toastui-editor-ww-container > .toastui-editor > .ProseMirror");

        if (vulnerabilityType.toLowerCase() === "xss") {
            vulnerabilityDetail.innerHTML = `
            <h2>XSS (Cross-Site Scripting)</h2>
            <p><strong>취약점 개요:</strong> 웹 애플리케이션에서 사용자 입력 처리 미흡으로 인한 악성 스크립트 실행.</p>
            <p><strong>취약점 상세 설명:</strong> 사용자 입력이 검증, 인코딩 없이 동적 웹 페이지에 포함되어 실행될 때 발생합니다. 이는 공격자가 사용자의 브라우저에서 악성 스크립트를 실행할 수 있게 하여, 사용자의 세션 정보 탈취, 사이트 가로채기 등의 행위를 가능하게 합니다.</p>
            <p><strong>취약점 발견 방법:</strong> 자동화된 스캐닝 도구 사용, 수동 검증을 통한 코드 리뷰.</p>
            <p><strong>취약점 발생 원인:</strong> 사용자 입력이 웹 페이지로 직접 전달될 때 필요한 검증 및 인코딩이 이루어지지 않은 경우.</p>
            <p><strong>취약점 악용 시나리오:</strong> 공격자는 악성 스크립트를 통해 사용자의 쿠키를 탈취하거나, 사용자가 보는 웹 페이지 내용을 변경할 수 있습니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {
            vulnerabilityDetail.innerHTML = `
            <h2>SQLi (SQL Injection)</h2>
            <p><strong>취약점 개요:</strong> 데이터베이스 쿼리 조작을 통한 무단 데이터 접근 및 조작.</p>
            <p><strong>취약점 상세 설명:</strong> 사용자 입력이 적절히 이스케이프 처리되지 않아 SQL 쿼리를 조작할 수 있게 됩니다. 이는 데이터베이스에 저장된 중요한 정보의 무단 접근, 수정, 삭제를 가능하게 합니다.</p>
            <p><strong>취약점 발견 방법:</strong> 자동화된 도구의 사용, SQL 주입 공격 패턴을 이용한 수동 테스트.</p>
            <p><strong>취약점 발생 원인:</strong> 사용자 입력이 데이터베이스 쿼리에 직접 포함될 때 적절한 검증 및 이스케이프 처리가 이루어지지 않은 경우.</p>
            <p><strong>취약점 악용 시나리오:</strong> 공격자는 이 취약점을 통해 사용자의 개인정보 탈취, 데이터베이스 조작을 통한 애플리케이션 기능 장애 유발 등을 할 수 있습니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {
            vulnerabilityDetail.innerHTML = `
            <h2>SSRF (Server-Side Request Forgery)</h2>
            <p><strong>취약점 개요:</strong> 서버를 대신하여 악의적인 요청을 전송할 수 있게 하는 취약점.</p>
            <p><strong>취약점 상세 설명:</strong> 이 취약점을 통해 공격자는 서버를 조작하여 외부 시스템에 대한 요청을 보낼 수 있습니다. 이를 통해 내부 네트워크에 접근하거나 다른 취약점을 활용할 수 있습니다.</p>
            <p><strong>취약점 발견 방법:</strong> 수동 테스트, 네트워크 트래픽 분석을 통한 검증.</p>
            <p><strong>취약점 발생 원인:</strong> 서버가 사용자의 입력을 기반으로 외부 시스템에 요청을 보내는 경우, 이 입력에 대한 적절한 검증이 이루어지지 않은 상태에서 발생합니다.</p>
            <p><strong>취약점 악용 시나리오:</strong> 공격자는 이 취약점을 활용하여 내부 서비스에 접근하거나, 외부 서비스와의 연동을 통해 추가적인 공격을 시도할 수 있습니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {
            vulnerabilityDetail.innerHTML = `
            <h2>RCE (Remote Code Execution)</h2>
            <p><strong>취약점 개요:</strong> 원격에서 코드를 실행할 수 있게 하는 취약점.</p>
            <p><strong>취약점 상세 설명:</strong> 이 취약점을 통해 공격자는 원격에서 임의의 코드를 실행하여 시스템을 제어할 수 있습니다. 이는 시스템의 완전한 탈취, 데이터 유출 등을 가능하게 합니다.</p>
            <p><strong>취약점 발견 방법:</strong> 코드 분석, 취약점 스캔 도구의 사용, 공격 시뮬레이션을 통한 검증.</p>
            <p><strong>취약점 발생 원인:</strong> 외부 입력이 검증없이 시스템의 명령어 실행에 사용될 때 발생합니다.</p>
            <p><strong>취약점 악용 시나리오:</strong> 공격자는 이 취약점을 통해 시스템의 관리자 권한을 획득하고, 기밀 정보를 탈취하거나 시스템을 파괴할 수 있습니다.</p>
            `;
        }
        else {
            vulnerabilityDetail.innerHTML = '<p>misc</p>';
        }

        await sleep(1000);

        // 조치방안 완료

        const howToPatchDetail = document.querySelector("div[name='howToPatchDetail'] .toastui-editor-ww-container > .toastui-editor > .ProseMirror");

        if (vulnerabilityType.toLowerCase() === "xss") {
            howToPatchDetail.innerHTML = `
            <h2>XSS (Cross-Site Scripting) 조치 방안</h2>
            <p><strong>입력 검증:</strong> 모든 사용자 입력에 대해 적절한 검증을 수행합니다. 특히, HTML 태그와 같은 스크립트 요소를 포함하지 않도록 검증합니다.</p>
            <p><strong>출력 인코딩:</strong> 사용자 입력을 웹 페이지에 출력하기 전에 안전한 형식으로 인코딩합니다.</p>
            <p><strong>컨텐츠 보안 정책 (CSP):</strong> CSP를 구현하여 악성 스크립트의 실행을 방지합니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {
            howToPatchDetail.innerHTML = `
            <h2>SQLi (SQL Injection) 조치 방안</h2>
            <p><strong>파라미터화된 쿼리:</strong> SQL 쿼리에서 사용자 입력을 직접 조합하는 대신 파라미터화된 쿼리를 사용합니다.</p>
            <p><strong>입력 검증:</strong> 사용자 입력에 대한 엄격한 검증을 실시합니다.</p>
            <p><strong>최소 권한 원칙:</strong> 데이터베이스 접근에 있어 최소한의 권한만을 부여합니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {
            howToPatchDetail.innerHTML = `
            <h2>SSRF (Server-Side Request Forgery) 조치 방안</h2>
            <p><strong>요청 필터링:</strong> 서버가 외부 시스템으로의 요청을 보낼 때, 내부 URL 또는 민감한 자원에 대한 요청을 차단합니다.</p>
            <p><strong>타임아웃 설정:</strong> 외부 요청에 대해 적절한 타임아웃을 설정하여 공격자가 시스템 리소스를 고갈시키는 것을 방지합니다.</p>
            <p><strong>서비스 화이트리스트:</strong> 서버가 요청을 보낼 수 있는 외부 서비스의 화이트리스트를 관리합니다.</p>
            `;
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {
            howToPatchDetail.innerHTML = `
            <h2>RCE (Remote Code Execution) 조치 방안</h2>
            <p><strong>입력 검증:</strong> 시스템 명령어에 사용되는 모든 입력에 대해 엄격한 검증을 실시합니다.</p>
            <p><strong>안전한 API 사용:</strong> 가능하다면 시스템 명령어 실행 대신 안전한 API를 사용합니다.</p>
            <p><strong>최소 권한 원칙:</strong> 애플리케이션이 운영 시스템에서 실행되는 동안 필요한 최소한의 권한을 가지도록 합니다.</p>
            `;
        }
        else {
            howToPatchDetail.innerHTML = '<p>misc</p>';
        }

        await sleep(1000);

        // 취약점 정보 활용 및 비밀 유지 동의 완료
        var xpath = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[11]/label/div/div';
        var input = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        if (input) {
            input.click();
        }

        // 리포트 제목 완료

        if (vulnerabilityType.toLowerCase() === "xss") {
            var reportName = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[1]/input';
            var reportNameElement = document.evaluate(reportName, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
            if (reportNameElement && reportNameElement.tagName === 'INPUT') {
                setTextareaValue(reportNameElement, extractDomain(VulnURL) + '에서의 Cross Site Scripting');
            }
        }
        else if (vulnerabilityType.toLowerCase() === "sqli") {
            var reportName = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[1]/input';
            var reportNameElement = document.evaluate(reportName, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
            if (reportNameElement && reportNameElement.tagName === 'INPUT') {
                setTextareaValue(reportNameElement, extractDomain(VulnURL) + '에서의 SQL Injection');
            }
        }
        else if (vulnerabilityType.toLowerCase() === "ssrf") {
            var reportName = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[1]/input';
            var reportNameElement = document.evaluate(reportName, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
            if (reportNameElement && reportNameElement.tagName === 'INPUT') {
                setTextareaValue(reportNameElement, extractDomain(VulnURL) + '에서의 Server Side Request Forgery');
            }
        }
        else if (vulnerabilityType.toLowerCase() === "rce") {
            var reportName = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[1]/input';
            var reportNameElement = document.evaluate(reportName, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
            if (reportNameElement && reportNameElement.tagName === 'INPUT') {
                setTextareaValue(reportNameElement, extractDomain(VulnURL) + '에서의 Remote Code Execution');
            }
        }
        else {
            var reportName = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[1]/input';
            var reportNameElement = document.evaluate(reportName, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
            if (reportNameElement && reportNameElement.tagName === 'INPUT') {
                setTextareaValue(reportNameElement, extractDomain(VulnURL) + '에서의 MISC');
            }
        }


        await sleep(1000);

        // 발견 위치 완료

        var vulnerabilityLocation = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[2]/textarea';
        var vulnerabilityLocationElement = document.evaluate(vulnerabilityLocation, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    
        if (vulnerabilityLocationElement && vulnerabilityLocationElement.tagName === 'TEXTAREA') {
            setTextareaValue(vulnerabilityLocationElement, VulnURL);
        }

        await sleep(1000);

        // Attack Point 완료
        var attackPoint = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[4]/div[1]/textarea';
        var attackPointElement = document.evaluate(attackPoint, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
        
        if (attackPointElement && attackPointElement.tagName === 'TEXTAREA') {
            setTextareaValue(attackPointElement, 'Attack Point');
        }

        await sleep(1000);

        // Payload 완료
        var payLoad = '//*[@id="root"]/section/section/div/div[3]/div[2]/div[4]/div[2]/textarea';
        var payLoadElement = document.evaluate(payLoad, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
        
        if (payLoadElement && payLoadElement.tagName === 'TEXTAREA') {
            setTextareaValue(payLoadElement, 'PayLoad');
        }

        await sleep(1000);

    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", fillForm);
    } else {
        fillForm();
    }

})();
