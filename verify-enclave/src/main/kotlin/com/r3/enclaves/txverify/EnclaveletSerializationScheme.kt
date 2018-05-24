/*
 * R3 Proprietary and Confidential
 *
 * Copyright (c) 2018 R3 Limited.  All rights reserved.
 *
 * The intellectual and technical concepts contained herein are proprietary to R3 and its suppliers and are protected by trade secret law.
 *
 * Distribution of this file or any portion thereof via any medium without the express permission of R3 is strictly prohibited.
 */

@file:JvmName("EnclaveletSerializationScheme")
package com.r3.enclaves.txverify

import net.corda.core.serialization.SerializationContext
import net.corda.core.serialization.internal.SerializationEnvironmentImpl
import net.corda.core.serialization.internal.nodeSerializationEnv
import net.corda.core.utilities.toHexString
import net.corda.serialization.internal.AMQP_P2P_CONTEXT
import net.corda.serialization.internal.CordaSerializationMagic
import net.corda.serialization.internal.SerializationFactoryImpl
import net.corda.serialization.internal.amqp.AbstractAMQPSerializationScheme
import net.corda.serialization.internal.amqp.SerializerFactory
import net.corda.serialization.internal.amqp.amqpMagic

@Suppress("UNUSED")
private class EnclaveletSerializationScheme {
    /*
     * Registers the serialisation schemes as soon as this class is loaded into the JVM.
     */
    private companion object {
        init {
            nodeSerializationEnv = SerializationEnvironmentImpl(
                SerializationFactoryImpl(HashMap()).apply {
                    registerScheme(AMQPVerifierSerializationScheme)
                },
                /**
                 * Even though default context is set to Amqp P2P, the encoding will be adjusted depending on the
                 * incoming request received.
                 */
                AMQP_P2P_CONTEXT)

            /*
             * Ensure that we initialise JAXP before blacklisting is enabled.
             */
            ByteArray(0).toHexString()
        }
    }
}

private object AMQPVerifierSerializationScheme : AbstractAMQPSerializationScheme(emptySet(), HashMap()) {
    override fun canDeserializeVersion(magic: CordaSerializationMagic, target: SerializationContext.UseCase): Boolean {
        return magic == amqpMagic && target == SerializationContext.UseCase.P2P
    }

    override fun rpcClientSerializerFactory(context: SerializationContext): SerializerFactory = throw UnsupportedOperationException()
    override fun rpcServerSerializerFactory(context: SerializationContext): SerializerFactory = throw UnsupportedOperationException()
}
