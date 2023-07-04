package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.jws.JwsSigned
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull

class JwsSerializationTest : FreeSpec({

    "mDL as JWS" {
        // from ISO/IEC 18013-5:2021
        val input = """ {
            "doctype": "org.iso.18013.5.1.mDL",
            "namespaces": {
                "org.iso.18013.5.1": {
                  "family_name": "Doe",
                  "given_name": "Jane",
                  "issue_date": "2019-10-20",
                  "expiry_date": "2024-10-20",
                  "document_number": "123456789",
                  "portrait": "_9j_4AAQSkZJRgABAQEAkACQAAD_2wBDABMNDhEODBMRDxEVFBMXHTAfHRoaHToqLCMwRT1JR0Q9Q0FMVm1dTFFoUkFDX4JgaHF1e3x7SlyGkIV3j214e3b_2wBDARQVFR0ZHTgfHzh2T0NPdnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnb_wAARCAAYAGQDASIAAhEBAxEB_8QAGwAAAwEAAwEAAAAAAAAAAAAAAAUGBAECAwf_xAAyEAABAwMDAgUCAwkAAAAAAAABAgMEAAURBhIhEzEUFVFhcSJBB4GhFjVCUnORssHx_8QAFQEBAQAAAAAAAAAAAAAAAAAAAAH_xAAaEQEBAQADAQAAAAAAAAAAAAAAAUERITFh_9oADAMBAAIRAxEAPwClu94i2iMpx9aSvH0NA_Us-w_3Xnp-8-dwlyOh0NrhRt37s8A5zgetK9R6fjLbuN0dUtbvSyhPZKSABn37Ufh_-5X_AOuf8U0hXeZq8InORLfb3py2iQooOO3fGAePet1i1BHvTbmxCmXWuVoUc4HqDUlbkzJ1_mu6dcEUEEqLpBBBPpg9_wBPWvXTS0tM3mMtC_H9FZK92RxkEfOTTC-mr2tUl10Qbc9KZa5W6FYAHrwDx84p3Z7vHvEPxEfcnadq0q7pNTehun5PcN2O_wBXxt_7XhoZhUqDdY5UUodQlG7GcEhQzQN7zrCLbX0sx20zF_x7XMBPtnByacXG4MW2CuVJJCEjsOST9gKgdVWeNZlw2Y24lSVFa1HJUcivoT6o6Y48WWg2eD1cY_WmGpn9tykIddtL6IqzhLu7v8cYP96qYz6JUdt9o5bcSFJPsai9YRpaoqJDLzCrQgp6bTJAxxjPAx-p70ya1VAgWqApUd9KHWyEIbAVt2nbjJIpg36ivosbDTnQ66nFFITv24wO_Y0lja88RJaZ8u29RYTnr5xk4_lrm-so1KxAkx5keMjnaiSoJUSVAdhn0rHc3rrpm5x1KuTs1t3koXnBweRgk4-RSe9lXlFcA5GaKJyz3KJ4-3vxd_T6qCndjOPyrJp-zeSQlx-v19zhXu2bccAYxk-lFFFLJOjk-MXJt1wegledwSM9_sCCOPat1i05GswcUlannnBtUtQxx6AUUUC5_RSes6YNxeiMu8LaCSQR6dxx85p3ZrRHs0ToR9ysnctau6jRRQYdQ6b88eZc8V0OkCMdPdnP5imVxtzFyhKiyQShX3HdJ9RRRT4J0aIUUJYcuz6oqVZDO3gfHOM9_tVPDitQorcdhO1tsYAoooF190_GvaEFxSmnkcJcTzx6EfcVhiaPSma3JuM96epvG1Kxgcdgck5HtRRSClooooP_2Q",
                  "driving_privileges": [
                    {
                      "vehicle_category_code": "A",
                      "issue_date": "2018-08-09",
                      "expiry_date": "2024-10-20"
                    },
                    {
                      "vehicle_category_code": "B",
                      "issue_date": "2017-02-23",
                      "expiry_date": "2024-10-20"
                    }
                  ],
                  "birth_date": "1970-01-01",
                  "issuing_country": "AT",
                  "issuing_authority": "LPD Steiermark",
                  "un_distinguishing_sign": "AT"
                }
            },
            "iat": 1609855200,
            "exp": 1609855320
        }
        """.trimIndent()

        val mdlJws = MobileDrivingLicenceJws.deserialize(input)

        mdlJws.shouldNotBeNull()
        println(mdlJws.namespaces.mdl)
    }
})
